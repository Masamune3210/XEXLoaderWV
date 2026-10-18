.text
.p2align 2
.globl xenon_save_fpr_bank
.type xenon_save_fpr_bank,@function
xenon_save_fpr_bank:
  stfd 0,0x988(3)
  mffs 0
  stfd 1,0x990(3)
  stfd 2,0x998(3)
  stfd 3,0x9a0(3)
  stfd 4,0x9a8(3)
  stfd 5,0x9b0(3)
  stfd 6,0x9b8(3)
  stfd 7,0x9c0(3)
  stfd 8,0x9c8(3)
  stfd 9,0x9d0(3)
  stfd 10,0x9d8(3)
  stfd 11,0x9e0(3)
  stfd 12,0x9e8(3)
  stfd 13,0x9f0(3)
  stfd 14,0x9f8(3)
  stfd 15,0xa00(3)
  stfd 16,0xa08(3)
  stfd 17,0xa10(3)
  stfd 18,0xa18(3)
  stfd 19,0xa20(3)
  stfd 20,0xa28(3)
  stfd 21,0xa30(3)
  stfd 22,0xa38(3)
  stfd 23,0xa40(3)
  stfd 24,0xa48(3)
  stfd 25,0xa50(3)
  stfd 26,0xa58(3)
  stfd 27,0xa60(3)
  stfd 28,0xa68(3)
  stfd 29,0xa70(3)
  stfd 30,0xa78(3)
  stfd 31,0xa80(3)
  stfd 0,0x980(3)
  blr
.size xenon_save_fpr_bank,.-xenon_save_fpr_bank
.p2align 2
.globl xenon_add_f64
.type xenon_add_f64,@function
xenon_add_f64:
  fadd 1,1,2
  blr
.size xenon_add_f64,.-xenon_add_f64
.p2align 2
.globl xenon_save_fpr_wrapper
.type xenon_save_fpr_wrapper,@function
xenon_save_fpr_wrapper:
  mflr 0
  std 0,0x10(1)
  stdu 1,-0x20(1)
  bl xenon_save_fpr_bank
  addi 1,1,0x20
  ld 0,0x10(1)
  mtlr 0
  blr
.size xenon_save_fpr_wrapper,.-xenon_save_fpr_wrapper
.p2align 2
.globl xenon_call_add_f64
.type xenon_call_add_f64,@function
xenon_call_add_f64:
  mflr 0
  std 0,0x10(1)
  stdu 1,-0x20(1)
  bl xenon_add_f64
  addi 1,1,0x20
  ld 0,0x10(1)
  mtlr 0
  blr
.size xenon_call_add_f64,.-xenon_call_add_f64
