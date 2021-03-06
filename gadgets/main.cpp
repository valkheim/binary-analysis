#include <string>
#include <deque>
#include <fmt/core.h>
#include <optional>
#include <iostream>

#include <Zydis/Zydis.h>
#include "loader/loader.hpp"

const uint8_t x86_op_ret = 0xc3;
const uint8_t max_last_instructions = 4;
const uint64_t base_addr = 0x007FFFFFFF400000;

static void display_gadgets(const Loader::Section *text, ZydisDecoder decoder, ZydisFormatter *formatter)
{
  ZyanU64 runtime_address = base_addr + text->vma;
  auto last_instructions = std::deque<std::string>(max_last_instructions);


  for (uint64_t i = 0 ; i < text->size ; ++i)
  {
    char buffer[256];
    ZydisDecodedInstruction instruction;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, text->bytes + i, text->size - i, &instruction)))
    {
      last_instructions.clear();
    } else {
      ZydisFormatterFormatInstruction(formatter, &instruction, buffer, sizeof(buffer), runtime_address);
      last_instructions.emplace_back(fmt::format("{:#x}: {}", runtime_address, buffer));
    }

    runtime_address += 1;
    if (last_instructions.size() > max_last_instructions)
      last_instructions.pop_front();

    if (text->bytes[i] != x86_op_ret) // weak
      continue;

    puts("--");
    for (const auto &insn: last_instructions)
      printf("%s\n", insn.c_str());
  }
}

static std::optional<ZydisDecoder> get_decoder(Loader::Binary *binary)
{
  ZydisDecoder decoder;
  ZydisAddressWidth width;
  if (binary->arch != Loader::Binary::ARCH_X86)
  {
    fprintf(stderr, "Zydis is only compatible with x86/x86-64\n");
    return {};    
  }

  switch (binary->bits)
  {
    case 32:
      width = ZYDIS_ADDRESS_WIDTH_32;
      break;
    case 64:
      width = ZYDIS_ADDRESS_WIDTH_64;
      break;
    default:
      return {};
  }

  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, width);
  return decoder;
}

static int find_gadgets(Loader::Binary *bin)
{
  const auto text = bin->get_text_section();
  if (!text)
  {
    fprintf(stderr, "No text section\n");
    return 1;
  }

  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL); // intel style > all

  const auto decoder = get_decoder(bin);
  if (!decoder)
  {
    fprintf(stderr, "Cannot get decoder\n");
    return 1;    
  }
  display_gadgets(text, *decoder, &formatter);

  return 0;
}


int main(int ac, char **av)
{
  Loader::Binary bin;
  const auto &filename = std::string(av[1]);
  if (load_binary(filename, &bin, Loader::Binary::BIN_TYPE_AUTO) < 0)
  {
    fprintf(stderr, "Cannot load binary (%s)\n", filename.c_str());
    return 1;
  }

  if (find_gadgets(&bin) < 0)
  {
    fprintf(stderr, "Cannot find gadgets\n");
    return 1;
  }

  unload_binary(&bin);
  return 0;
}
