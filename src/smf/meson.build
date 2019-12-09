# Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>

# This file is part of Open5GS.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

smf_conf = configuration_data()

smf_headers = ('''
    net/if.h
    netinet/ip.h
    netinet/ip6.h
    netinet/ip_icmp.h
    netinet/icmp6.h
'''.split())

foreach h : smf_headers
    if cc.has_header(h)
        define = 'HAVE_' + h.underscorify().to_upper()
        smf_conf.set(define, 1)
    endif
endforeach

if have_func_kqueue
    smf_conf.set('HAVE_KQUEUE', 1)
endif

configure_file(output : 'smf-config.h', configuration : smf_conf)

libsmf_sources = files('''
    smf-ipfw.h
    smf-event.h
    smf-context.h
    smf-sm.h
    smf-gtp-path.h
    smf-s5c-build.h
    smf-s5c-handler.h
    smf-fd-path.h
    smf-gx-handler.h
    smf-pfcp-path.h

    smf-ipfw.c
    smf-init.c
    smf-event.c
    smf-context.c
    smf-sm.c
    smf-gtp-path.c
    smf-s5c-build.c
    smf-s5c-handler.c 
    smf-fd-path.c
    smf-gx-handler.c 
    smf-pfcp-path.c
'''.split())

libsmf = static_library('smf',
    sources : libsmf_sources,
    link_with : libipfw,
    dependencies : [
        libapp_dep, libdiameter_gx_dep, libgtp_dep, libpfcp_dep, libipfw_dep
    ],
    install : false)

libsmf_dep = declare_dependency(
    link_with : libsmf,
    dependencies : [
        libapp_dep, libdiameter_gx_dep, libgtp_dep, libpfcp_dep, libipfw_dep
    ])

smf_sources = files('''
    app-init.c
    ../main.c
'''.split())

executable('open5gs-smfd',
    sources : smf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/smf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : libsmf_dep,
    install_rpath : libdir,
    install : true)
