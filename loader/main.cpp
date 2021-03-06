#include "loader/loader.hpp"

int main(int ac, char **av)
{
  Loader::Binary bin;
  const auto filename = std::string(av[1]);

  if (load_binary(filename, &bin, Loader::Binary::BIN_TYPE_AUTO) < 0)
  {
    fprintf(stderr, "Cannot load binary (%s)\n", filename.c_str());
    return 1;
  }

  printf(
    "Binary '%s' %s%s (%u bits) entry@0x%016jx\n",
    bin.filename.c_str(),
    bin.type_str.c_str(),
    bin.arch_str.c_str(),
    bin.bits,
    bin.entry
  );

  puts("Sections:");
  for (const auto &section : bin.sections)
  {
    printf(
      "  0x%016jx %-8ju %-20s %s\n",
      section.vma, section.size, section.name.c_str(),
      section.type == Loader::Section::SEC_TYPE_CODE ? "CODE" : "DATA"
    );
  }

  puts("Symbols:");
  for (const auto &symbol : bin.symbols)
  {
    printf(
      "  %-40s 0x%016jx %s\n",
      symbol.name.c_str(), symbol.addr,
      (symbol.type & Loader::Symbol::SYM_TYPE_FUNC) ? "FUNC" : ""
    );
  }

  unload_binary(&bin);
  return 0;
}

