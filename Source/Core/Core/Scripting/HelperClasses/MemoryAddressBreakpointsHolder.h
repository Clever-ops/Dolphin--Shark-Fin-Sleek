#ifndef MEMORY_ADDRESS_BREAKPOINTS_HOLDER_IMPL
#define MEMORY_ADDRESS_BREAKPOINTS_HOLDER_IMPL

#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

class MemoryAddressBreakpointsHolder
{
public:
  MemoryAddressBreakpointsHolder();
  ~MemoryAddressBreakpointsHolder();
  void AddReadBreakpoint(unsigned int addr);
  bool ContainsReadBreakpoint(unsigned int addr);
  void RemoveReadBreakpoint(unsigned int addr);
  void AddWriteBreakpoint(unsigned int addr);
  bool ContainsWriteBreakpoint(unsigned int addr);
  void RemoveWriteBreakpoint(unsigned int addr);
  void RemoveAllBreakpoints();

private:
  std::vector<unsigned int> read_breakpoint_addresses;
  std::vector<unsigned int> write_breakpoint_addresses;
};

#ifdef __cplusplus
}
#endif

#endif
