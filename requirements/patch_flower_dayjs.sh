#!/bin/sh

set -eu

flower_dir=$(python -c 'import pathlib, flower; print(pathlib.Path(flower.__file__).parent)')
static_dir="${flower_dir}/static/js"
base_template="${flower_dir}/templates/base.html"
flower_js="${static_dir}/flower.js"

install -m 0644 requirements/flower-dayjs/flower-dayjs-1.11.21.min.js "${static_dir}/"

sed -i.bak \
  -e "s@js/moment-2.29.4.min.js@js/flower-dayjs-1.11.21.min.js@" \
  -e "/js\/moment-timezone-with-data-2.29.4.min.js/d" \
  "${base_template}"

sed -i.bak 's/moment\.unix/dayjs.unix/g' "${flower_js}"

rm -f \
  "${static_dir}/moment-2.29.4.min.js" \
  "${static_dir}/moment-timezone-with-data-2.29.4.min.js" \
  "${base_template}.bak" \
  "${flower_js}.bak"

grep -q "flower-dayjs-1.11.21.min.js" "${base_template}"
grep -q "dayjs.unix(timestamp)" "${flower_js}"
! grep -q "moment" "${base_template}"
! grep -q "moment\.unix" "${flower_js}"
