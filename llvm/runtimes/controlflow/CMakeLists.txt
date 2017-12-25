set(SOURCES
  ControlFlowRuntime.c
)

include(AddLLVM)

add_llvm_library( control_flow_rt-static ${SOURCES} )
set_target_properties( control_flow_rt-static
  PROPERTIES
  OUTPUT_NAME "control_flow_rt" )

set(BUILD_SHARED_LIBS ON)
add_llvm_library( control_flow_rt-shared ${SOURCES} )
set_target_properties( control_flow_rt-shared
  PROPERTIES
  OUTPUT_NAME "control_flow_rt" )
