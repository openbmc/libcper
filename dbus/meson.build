cper_dbus_dependencies = []

libsystemd = dependency('libsystemd')
cper_dbus_dependencies += libsystemd

sdbusplus = dependency('sdbusplus')
cper_dbus_dependencies += sdbusplus

executable(
    'cper-dbus',
    'main.cpp',
    dependencies: cper_dbus_dependencies,
    install: true,
    install_dir: join_paths(get_option('libexecdir'), meson.project_name()),
)

systemd_service_unit_conf = configuration_data()
systemd_service_unit_conf.set(
    'LIBEXECDIR',
    join_paths(
        get_option('prefix'),
        get_option('libexecdir'),
        meson.project_name(),
    ),
)

systemd_service_unit = configure_file(
    configuration: systemd_service_unit_conf,
    input: 'systemd/xyz.openbmc_project.CPERRepository1.service.in',
    output: 'xyz.openbmc_project.CPERRepository1.service',
)

systemd_system_unit_dir = dependency('systemd').get_variable(
    'systemd_system_unit_dir',
)

install_data(systemd_service_unit, install_dir: systemd_system_unit_dir)

dbus_system_bus_services_dir = dependency('dbus-1').get_variable(
    'system_bus_services_dir',
    pkgconfig_define: ['prefix', get_option('prefix')],
)

install_data(
    'systemd/dbus/xyz.openbmc_project.CPERRepository1.service',
    install_dir: dbus_system_bus_services_dir,
)

install_data(
    'systemd/dbus/xyz.openbmc_project.CPERRepository1.conf',
    install_dir: get_option('datadir') / 'dbus-1' / 'system.d',
)
