#include <stdio.h>
#include "pin.H"

static void show_routines(IMG img, void *)
{
  if (!IMG_Valid(img))
    return;

  // Iterate sections
  for (SEC sec = IMG_SecHead(img) ; SEC_Valid(sec) ; sec = SEC_Next(sec))
  {
    // Iterate routines
    for (RTN rtn = SEC_RtnHead(sec) ; RTN_Valid(rtn) ; rtn = RTN_Next(rtn))
    {
      printf("%lx: %s\n", RTN_Address(rtn), RTN_Name(rtn).c_str());
    }
  }
}

int main(int ac, char **av)
{
  PIN_InitSymbols();
  if (PIN_Init(ac, av))
    return 1;

  puts("Hello from profiler pintool");

  IMG_AddInstrumentFunction(show_routines, NULL);

  PIN_StartProgram();
  return 0;
}
