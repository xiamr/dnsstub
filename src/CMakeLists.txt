
set(SOURCE_FILES main.cpp Config.cpp Global.cpp DnsQueryStatistics.cpp Dns.cpp Cache.cpp DnsHandler.cpp SetupLog.cpp SetupInit.cpp)
add_executable(dnsstub ${SOURCE_FILES})
INSTALL(TARGETS dnsstub RUNTIME DESTINATION bin)
