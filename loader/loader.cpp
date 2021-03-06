#include <bfd.h>
#include "loader.hpp"

static bfd *open_bfd(const std::string &fname)
{
  static bool init = false;
  if (!init)
  {
    bfd_init();
    init = true;
  }

  bfd *bfd_h = bfd_openr(fname.c_str(), NULL);
  if (!bfd_h)
  {
    fprintf(stderr, "failed to open binary '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  if (!bfd_check_format(bfd_h, bfd_object))
  {
    fprintf(stderr, "file '%s' isn't an executable (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  bfd_set_error(bfd_error_no_error);
  if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour)
  {
    fprintf(stderr, "unrecognized format for '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  return bfd_h;
}

static int load_dynsym_bfd(bfd *bfd_h, Loader::Binary *bin)
{
  int     ret;
  asymbol **bfd_dynsym = NULL;
  Loader::Symbol  *sym;

  long n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  if (n < 0)
  {
    fprintf(stderr, "failed to read dynamic symtab (%s)\n", bfd_errmsg(bfd_get_error()));
    goto fail;
  }
  else if (n)
  {
    bfd_dynsym = (asymbol**)malloc(n);
    if (!bfd_dynsym)
    {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }

    long nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
    if (nsyms < 0)
    {
      fprintf(stderr, "failed to read dynamic symtab (%s)\n", bfd_errmsg(bfd_get_error()));
      goto fail;
    }

    for (auto i = 0 ; i < nsyms ; ++i)
    {
      if (bfd_dynsym[i]->flags & BSF_FUNCTION)
      {
        bin->symbols.emplace_back(Loader::Symbol());
        sym = &bin->symbols.back();
        sym->type = Loader::Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_dynsym[i]->name);
        sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if (bfd_dynsym)
    free(bfd_dynsym);

  return ret;
}

static int load_symbols_bfd(bfd *bfd_h, Loader::Binary *bin)
{
  int     ret;
  asymbol **bfd_symtab = NULL;
  Loader::Symbol  *sym;

  long n = bfd_get_symtab_upper_bound(bfd_h);
  if (n < 0)
  {
    fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if (n) {
    bfd_symtab = (asymbol**)malloc(n);
    if (!bfd_symtab)
    {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }

    long nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if (nsyms < 0)
    {
      fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
      goto fail;
    }

    for (auto i = 0 ; i < nsyms ; ++i)
    {
      if (bfd_symtab[i]->flags & BSF_FUNCTION)
      {
        bin->symbols.emplace_back(Loader::Symbol());
        sym = &bin->symbols.back();
        sym->type = Loader::Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_symtab[i]->name);
        sym->addr = bfd_asymbol_value(bfd_symtab[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if (bfd_symtab)
    free(bfd_symtab);

  return ret;
}

static int load_sections_bfd(bfd *bfd_h, Loader::Binary *bin)
{
  for (asection *bfd_sec = bfd_h->sections ; bfd_sec ; bfd_sec = bfd_sec->next)
  {
    const auto flags = bfd_section_flags(bfd_sec);

    auto sectype = Loader::Section::SEC_TYPE_NONE;
    if (flags & SEC_CODE)
      sectype = Loader::Section::SEC_TYPE_CODE;

    else if (flags & SEC_DATA)
      sectype = Loader::Section::SEC_TYPE_DATA;

    else
      continue;

    uint64_t vma = bfd_section_vma(bfd_sec);
    uint64_t size = bfd_section_size(bfd_sec);
    const char *name = bfd_section_name(bfd_sec);
    if (!name)
      name = "unknow";

    bin->sections.push_back(Loader::Section());
    auto sec = &bin->sections.back();
    sec->binary = bin;
    sec->name = std::string(name);
    sec->type = sectype;
    sec->vma = vma;
    sec->size = size;
    sec->bytes = (uint8_t*)malloc(size);
    if (!sec->bytes)
    {
      fprintf(stderr, "out of memory\n");
      return -1;
    }

    if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size))
    {
      fprintf(stderr, "failed to read section '%s' (%s)\n", name, bfd_errmsg(bfd_get_error()));
      return -1;
    }
  }

  return 0;
}

static int load_binary_bfd(const std::string &fname, Loader::Binary *bin, Loader::Binary::BinaryType type)
{
  int ret = -1;
  const bfd_arch_info_type *bfd_info = NULL;
  bfd *bfd_h = open_bfd(fname);
  if (!bfd_h)
    goto fail;

  bin->filename = std::string(fname);
  bin->entry    = bfd_get_start_address(bfd_h);
  bin->type_str = std::string(bfd_h->xvec->name);
  switch (bfd_h->xvec->flavour)
  {
    case bfd_target_elf_flavour:
      bin->type = Loader::Binary::BIN_TYPE_ELF;
      break;
   case bfd_target_coff_flavour:
      bin->type = Loader::Binary::BIN_TYPE_PE;
      break;
   case bfd_target_unknown_flavour:
   default:
      fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
      goto fail;
  }

  bfd_info = bfd_get_arch_info(bfd_h);
  bin->arch_str = std::string(bfd_info->printable_name);
  switch (bfd_info->mach)
  {
    case bfd_mach_i386_i386:
      bin->arch = Loader::Binary::ARCH_X86;
      bin->bits = 32;
      break;
    case bfd_mach_x86_64:
      bin->arch = Loader::Binary::ARCH_X86;
      bin->bits = 64;
      break;
    default:
      fprintf(stderr, "unsupported arch (%s)\n", bfd_info->printable_name);
      goto fail;
  }

  load_symbols_bfd(bfd_h, bin);
  load_dynsym_bfd(bfd_h, bin);
  if (load_sections_bfd(bfd_h, bin) < 0)
    goto fail;

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if (bfd_h)
    bfd_close(bfd_h);

  return ret;
}

int load_binary(const std::string &fname, Loader::Binary *bin, Loader::Binary::BinaryType type)
{
  return load_binary_bfd(fname, bin, type);
}

void unload_binary(Loader::Binary *bin)
{
  for (const auto &section : bin->sections)
  {
    if (section.bytes)
      free(section.bytes);
  }
}