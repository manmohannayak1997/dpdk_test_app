project('test-app', 'c')

if host_machine.system() == 'windows'
    message('Not supported on Windows')
    subdir_done()
endif

sources = files('test-app.c')
dpdk_dep = dependency('dpdk', modules : [
    'eal', 'malloc', 'ip', 'udp', 'tcp'
], required : true)

executable('test-app',
    sources,
    dependencies : dpdk_dep,
    install : false
)