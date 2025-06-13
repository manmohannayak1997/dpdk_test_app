# SPDX-License-Identifier: BSD-3-Clause

sources = files('test-app.c')

deps = ['eal', 'mbuf', 'ether', 'malloc', 'net', 'ip_frag']

dpdk_deps = []
foreach d: deps
    var_name = get_option('default_library') + '_rte_' + d
    if not is_variable(var_name)
        error('Missing DPDK library: @0@. Please enable it with -Denable_libs=@0@'.format(d))
    endif
    dpdk_deps += [get_variable(var_name)]
endforeach

executable('dpdk-test-app',
    sources,
    dependencies: dpdk_deps,
    install: true,
)
