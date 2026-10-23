# Builds mod_security2.so (ModSecurity 2.9.x) for Windows x64 against an
# Apache Lounge VS17 SDK. Intended to run on a Windows host with MSVC
# (Visual Studio 2022 generator), e.g. GitHub Actions windows-2022.
#
# Required cache variables:
#   MODSEC_SRC     - extracted ModSecurity source tree (contains apache2/)
#   APACHE_SDK     - Apache Lounge Apache24 directory (include/ + lib/)
#   LIBXML2_PREFIX - install prefix of a static libxml2 build
cmake_minimum_required(VERSION 3.20)
project(mod_security2 C)

set(MODSEC_SRC "" CACHE PATH "ModSecurity source tree")
set(APACHE_SDK "" CACHE PATH "Apache Lounge Apache24 dir")
set(LIBXML2_PREFIX "" CACHE PATH "libxml2 static install prefix")

foreach(v MODSEC_SRC APACHE_SDK LIBXML2_PREFIX)
    if(NOT ${v})
        message(FATAL_ERROR "${v} must be set")
    endif()
endforeach()

set(A2 ${MODSEC_SRC}/apache2)

set(SOURCES
    ${A2}/mod_security2.c
    ${A2}/apache2_config.c
    ${A2}/apache2_io.c
    ${A2}/apache2_util.c
    ${A2}/re.c
    ${A2}/re_operators.c
    ${A2}/re_actions.c
    ${A2}/re_tfns.c
    ${A2}/re_variables.c
    ${A2}/msc_logging.c
    ${A2}/msc_xml.c
    ${A2}/msc_multipart.c
    ${A2}/modsecurity.c
    ${A2}/msc_parsers.c
    ${A2}/msc_util.c
    ${A2}/msc_pcre.c
    ${A2}/persist_dbm.c
    ${A2}/msc_reqbody.c
    ${A2}/msc_geo.c
    ${A2}/msc_gsb.c
    ${A2}/msc_crypt.c
    ${A2}/msc_tree.c
    ${A2}/msc_unicode.c
    ${A2}/acmp.c
    ${A2}/msc_lua.c
    ${A2}/msc_release.c
    ${A2}/msc_status_engine.c
    ${A2}/msc_remote_rules.c
    ${A2}/msc_json.c
    ${A2}/others/libinjection/src/libinjection_html5.c
    ${A2}/others/libinjection/src/libinjection_sqli.c
    ${A2}/others/libinjection/src/libinjection_xss.c
)

add_library(mod_security2 SHARED ${SOURCES})

set_target_properties(mod_security2 PROPERTIES
    OUTPUT_NAME mod_security2
    PREFIX ""
    SUFFIX ".so"
)

target_include_directories(mod_security2 PRIVATE
    ${A2}
    ${MODSEC_SRC}
    ${APACHE_SDK}/include
    ${LIBXML2_PREFIX}/include/libxml2
)

# PCRE2 is the default regex backend in 2.9.15 (no WITH_PCRE define).
# JIT failure falls back to pcre2_match at runtime, so WITH_PCRE_JIT is safe.
# No WITH_CURL / WITH_REMOTE_RULES / WITH_LUA / WITH_YAJL: minimal module.
target_compile_definitions(mod_security2 PRIVATE
    WIN32
    WINNT
    inline=APR_INLINE
    WITH_PCRE_JIT
    PCRE2_STATIC
    LIBXML_STATIC
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(mod_security2 PRIVATE /W3 /wd4244 /wd4018)
endif()

find_library(LIBXML2_LIB NAMES libxml2s libxml2 xml2s xml2
    PATHS ${LIBXML2_PREFIX}/lib NO_DEFAULT_PATH REQUIRED)

target_link_libraries(mod_security2 PRIVATE
    ${APACHE_SDK}/lib/libhttpd.lib
    ${APACHE_SDK}/lib/libapr-1.lib
    ${APACHE_SDK}/lib/libaprutil-1.lib
    ${APACHE_SDK}/lib/pcre2-8-static.lib
    ${LIBXML2_LIB}
    ws2_32
    iphlpapi
    bcrypt
)
