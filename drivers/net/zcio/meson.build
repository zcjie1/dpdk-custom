# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources += files(
        'zcio.c',
)
deps += ['kvargs', 'bus_vdev', 'ethdev']