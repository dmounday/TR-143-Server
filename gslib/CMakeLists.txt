set (SRC_FILE_LIST
src/event.c
src/ipv4ipv6.c
src/protocol.c
src/utils.c
src/wget.c
src/www.c
src/md5.c
)

add_subdirectory(auxsrc)
add_library(gslib ${SRC_FILE_LIST})

