#!/usr/bin/env python3
import argparse
import os
import sys
import time
import uuid

import django


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(BASE_DIR, 'apps')

os.chdir(APP_DIR)
sys.path.insert(0, APP_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jumpserver.settings')
django.setup()

from django.core.files.storage import default_storage  # noqa: E402

from authentication.models import CommandFaceVerifyRecord  # noqa: E402
from authentication.services.camera import (  # noqa: E402
    CameraSystemClient,
    CameraSystemError,
    CameraTokenError,
    mask_id_number,
)


FINAL_STATUSES = {
    CommandFaceVerifyRecord.StatusChoices.passed,
    CommandFaceVerifyRecord.StatusChoices.failed,
    CommandFaceVerifyRecord.StatusChoices.error,
    CommandFaceVerifyRecord.StatusChoices.timeout,
    CommandFaceVerifyRecord.StatusChoices.token_failed,
    CommandFaceVerifyRecord.StatusChoices.camera_call_failed,
}


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            'Create a debug face-verify record, call the camera system, store the returned sign, '
            'and wait until the callback saves images to local storage.'
        )
    )
    parser.add_argument('--machine-ip', required=True, help='machineIp sent to the camera system')
    parser.add_argument('--user-name', required=True, help='userName sent to the camera system')
    parser.add_argument('--id-number', required=True, help='idNumber sent to the camera system')
    parser.add_argument('--timeout', type=int, default=90, help='seconds to wait for callback image save')
    parser.add_argument('--poll-interval', type=float, default=0.5, help='poll interval in seconds')
    parser.add_argument('--run-command', default='debug-call-camera-and-wait-callback')
    parser.add_argument('--org-id', default='')
    return parser.parse_args()


def create_record(args):
    return CommandFaceVerifyRecord.objects.create(
        session_id=uuid.uuid4(),
        user_id='debug-user',
        asset_id='debug-asset',
        account_id='debug-account',
        cmd_filter_acl_id=uuid.uuid4(),
        run_command=args.run_command,
        machine_ip=args.machine_ip,
        user_name=args.user_name,
        id_number_masked=mask_id_number(args.id_number),
        org_id=args.org_id,
        status=CommandFaceVerifyRecord.StatusChoices.created,
    )


def print_record(label, record):
    print(
        '{}: id={} sign={} status={} error={}'.format(
            label, record.id, record.sign or '', record.status, record.error_message or ''
        )
    )


def get_local_path(relative_path):
    if not relative_path:
        return ''
    try:
        return default_storage.path(relative_path)
    except Exception:
        return relative_path


def print_image_paths(record):
    face_abs = get_local_path(record.face_image_path)
    photo_abs = get_local_path(record.photo_image_path)
    print('face_image_path={}'.format(record.face_image_path))
    print('face_image_abs={}'.format(face_abs))
    print('face_image_size={}'.format(record.face_image_size))
    print('photo_image_path={}'.format(record.photo_image_path))
    print('photo_image_abs={}'.format(photo_abs))
    print('photo_image_size={}'.format(record.photo_image_size))
    if face_abs:
        print('face_image_exists={}'.format(os.path.exists(face_abs)))
    if photo_abs:
        print('photo_image_exists={}'.format(os.path.exists(photo_abs)))


def call_camera_and_store_sign(record, args):
    sign = CameraSystemClient().call_camera(args.machine_ip, args.user_name, args.id_number)
    record.sign = sign
    record.status = CommandFaceVerifyRecord.StatusChoices.waiting_photo
    record.error_message = ''
    record.save(update_fields=['sign', 'status', 'error_message', 'date_updated'])
    return sign


def wait_for_saved_images(record, args):
    deadline = time.time() + args.timeout
    last_status = None
    last_has_images = False

    while time.time() < deadline:
        record.refresh_from_db()
        has_images = bool(record.face_image_path and record.photo_image_path)

        if record.status != last_status or has_images != last_has_images:
            print_record('poll', record)
            last_status = record.status
            last_has_images = has_images

        if has_images:
            print('callback image save completed')
            print_image_paths(record)
            return 0

        if record.status in FINAL_STATUSES and not has_images:
            print('record reached final status before images were saved')
            return 2

        time.sleep(args.poll_interval)

    record.refresh_from_db()
    print('wait callback timeout after {} seconds'.format(args.timeout))
    print_record('timeout', record)
    if record.face_image_path or record.photo_image_path:
        print_image_paths(record)
        return 0
    return 3


def main():
    args = parse_args()
    record = create_record(args)
    print_record('created', record)

    try:
        sign = call_camera_and_store_sign(record, args)
        print('call camera success')
        print('sign={}'.format(sign))
        print_record('stored', record)
    except CameraTokenError as exc:
        record.status = CommandFaceVerifyRecord.StatusChoices.token_failed
        record.error_message = exc.message
        record.save(update_fields=['status', 'error_message', 'date_updated'])
        print_record('token_failed', record)
        return 1
    except CameraSystemError as exc:
        record.status = CommandFaceVerifyRecord.StatusChoices.camera_call_failed
        record.error_message = exc.message
        record.save(update_fields=['status', 'error_message', 'date_updated'])
        print_record('camera_failed', record)
        return 1

    print('waiting for camera callback to save images ...')
    return wait_for_saved_images(record, args)


if __name__ == '__main__':
    sys.exit(main())
