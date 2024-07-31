/*
* This file is part of libunwind.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "_UPT_internal.h"

#ifdef UNW_TARGET_AARCH64

static uint64_t swap_64 (uint64_t v)
{
  return ((v >>  0) & 0xFFull) << 56ull
       | ((v >>  8) & 0xFFull) << 48ull
       | ((v >> 16) & 0xFFull) << 40ull
       | ((v >> 24) & 0xFFull) << 32ull
       | ((v >> 32) & 0xFFull) << 24ull
       | ((v >> 40) & 0xFFull) << 16ull
       | ((v >> 48) & 0xFFull) <<  8ull
       | ((v >> 56) & 0xFFull) <<  0ull;
}

unw_word_t _UPT_ptrauth_insn_mask (unw_addr_space_t as, void *arg)
{
  struct UPT_info *ui = arg;
  pid_t pid = ui->pid;
  int ret;
  struct iovec iovec;
  uint64_t regset[2] = {0, 0};
  unw_word_t result = 0;

  iovec.iov_base = &regset;
  iovec.iov_len = sizeof (regset);

  ret = ptrace (PTRACE_GETREGSET, pid, NT_ARM_PAC_MASK, &iovec);
  if (ret != 0)
    {
      Debug (12, "Failed to fetch ptrauth instruction mask");
      return 0;
    }

  // regset[0] => data_mask
  // regset[1] => insn_mask
  result = regset[1];

  if (as->big_endian != target_is_big_endian ())
    {
      result = swap_64 (result);
    }

  return result;
}

#else

unw_word_t _UPT_ptrauth_insn_mask (unw_addr_space_t, void *)
{
  return 0;
}

#endif