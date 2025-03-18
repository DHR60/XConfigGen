add_compile_definitions(QS_HAS_JSON)
add_compile_definitions(QSERIALIZER_INCLUDED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/3rd/QSerializer)

list(APPEND HEADER_FILES
    "3rd/QSerializer/src/qserializer.h"
)
