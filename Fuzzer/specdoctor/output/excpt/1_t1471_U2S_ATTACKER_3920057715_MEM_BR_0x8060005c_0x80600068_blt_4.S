/* entry.S */

#include "encoding.h"
#include "template.h"

#if __riscv_xlen == 64
# define STORE    sd
# define LOAD     ld
# define REGBYTES 8
#else
# define STORE    sw
# define LOAD     lw
# define REGBYTES 4
#endif

#if TARGET == Boom || ISA == 1
#define PASS 1
#define FAIL 3
#else // Nutshell
#define PASS 0
#define FAIL 1
#endif

#define STACK_TOP (_end + 4096)

#if ATTACK == U2M && COMMIT == VICTIM
# error
#endif


#if ATTACK == U2S && COMMIT == VICTIM
#define v(sym) sym + USR_OFFSET
#else
#define v(sym) sym
#endif

#define vfn0 v(fn0)
#define vfn1 v(fn1)
#define vfn2 v(fn2)
#define vfn3 v(fn3)
#define vfn4 v(fn4)

#define vdata0 v(data0)
#define vdata1 v(data1)
#define vdata2 v(data2)
#define vdata3 v(data3)
#define vdata4 v(data4)
#define vdata5 v(data5)
#define vdata6 v(data5)
#define vdata7 v(data5)

    .section ".text","ax",@progbits
    .global _start
    .align 2
_start:
    j handle_reset

    /* NMI vector */
    .align 2
nmi_vector:
    j nmi_vector

    .global mtvec_handler
    .align 2
mtvec_handler:
    li a0, 1
    slli a0, a0, 63
    addi a0, a0, IRQ_M_EXT
    csrr t0, mcause
    bne a0, t0, 1f
    j xcpt
1:
#if ATTACK == S2M || ATTACK == U2M
#if COMMIT == VICTIM
    li gp, PASS
#else // ATTACKER
    li gp, FAIL
#endif // COMMIT
#else // U2S
    li gp, FAIL
#endif // ATTACK
    sim_exit

    .global stvec_handler
    .align 2
stvec_handler:
#if ATTACK == S2M
#if COMMIT == ATTACKER
    spdoc_check_c
#endif
    li gp, PASS
#elif ATTACK == U2M // && COMMIT == ATTACKER
    li a0, CAUSE_USER_ECALL
    csrr t0, scause
    li gp, PASS
    beq a0, t0, 1f
    li gp, FAIL
1:
#else // U2S
#if COMMIT == VICTIM
    li gp, PASS
#else
    li a0, CAUSE_USER_ECALL
    csrr t0, scause
    li gp, PASS
    beq a0, t0, 1f
    li gp, FAIL
1:
#endif // COMMIT
#endif // ATTACK
    sim_exit

handle_reset:
#if TARGET == Boom
    csrwi pmpcfg0, 0
#endif
    csrwi mstatus, 0

    /* Init xregs */
    li x1,  0
    li x2,  0
    li x3,  0
    li x4,  0
    li x5,  0
    li x6,  0
    li x7,  0
    li x8,  0
    li x9,  0
    li x10, 0
    li x11, 0
    li x12, 0
    li x13, 0
    li x14, 0
    li x15, 0
    li x16, 0
    li x17, 0
    li x18, 0
    li x19, 0
    li x20, 0
    li x21, 0
    li x22, 0
    li x23, 0
    li x24, 0
    li x25, 0
    li x26, 0
    li x27, 0
    li x28, 0
    li x29, 0
    li x30, 0
    li x31, 0

#if TARGET == Boom
    /* Init fregs */
    li a0, (MSTATUS_FS & (MSTATUS_FS >> 0))
    csrs mstatus, a0
    csrwi fcsr, 0
    fcvt.d.l f0,  zero
    fcvt.d.l f1,  zero
    fcvt.d.l f2,  zero
    fcvt.d.l f3,  zero
    fcvt.d.l f4,  zero
    fcvt.d.l f5,  zero
    fcvt.d.l f6,  zero
    fcvt.d.l f7,  zero
    fcvt.d.l f8,  zero
    fcvt.d.l f9,  zero
    fcvt.d.l f10, zero
    fcvt.d.l f11, zero
    fcvt.d.l f12, zero
    fcvt.d.l f13, zero
    fcvt.d.l f14, zero
    fcvt.d.l f15, zero
    fcvt.d.l f16, zero
    fcvt.d.l f17, zero
    fcvt.d.l f18, zero
    fcvt.d.l f19, zero
    fcvt.d.l f20, zero
    fcvt.d.l f21, zero
    fcvt.d.l f22, zero
    fcvt.d.l f23, zero
    fcvt.d.l f24, zero
    fcvt.d.l f25, zero
    fcvt.d.l f26, zero
    fcvt.d.l f27, zero
    fcvt.d.l f28, zero
    fcvt.d.l f29, zero
    fcvt.d.l f30, zero
    fcvt.d.l f31, zero
#endif

    la t0, mtvec_handler
    csrw mtvec, t0
    la t0, stvec_handler
    csrw stvec, t0

    la sp, STACK_TOP

    /* Memory layout configuration */
#if TARGET == Boom
    call pmp_boot
#endif
    call vm_boot

    /* Enable S-mode cycle reading */
    li a0, 1
#if TARGET == Boom
    csrs mcounteren, a0
#endif

    /* Set up external interrupt */
    li a0, MSTATUS_MPIE
    csrs mstatus, a0
    li a0, MIP_MEIP
    csrs mie, a0
#if ISA == 1
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
#else
    plic_on
#endif

prefix:
pfx:
pfx.entry:
pfx.bb0:
pfx.bb0.l0:         andi x19, x19, 0x3f8                      
                    la x22, data4                             
                    add x19, x19, x22                         
                    fld f0, 0(x19)                            
pfx.bb0.l1:         andi x22, x22, 0x3f8                      
                    la x21, data6                             
                    add x22, x22, x21                         
                    fld f1, 0(x22)                            
pfx.bb0.l2:         andi x19, x19, 0x3f8                      
                    la x20, data2                             
                    add x19, x19, x20                         
                    fld f2, 8(x19)                            
pfx.bb0.l3:         andi x21, x21, 0x3f8                      
                    la x19, data7                             
                    add x21, x21, x19                         
                    fld f3, 0(x21)                            
pfx.bb0.l4:         andi x19, x19, 0x3f8                      
                    la x22, data6                             
                    add x19, x19, x22                         
                    fld f4, 24(x19)                           
pfx.bb0.l5:         andi x19, x19, 0x3f8                      
                    la x22, data2                             
                    add x19, x19, x22                         
                    fld f5, 24(x19)                           
pfx.bb0.l6:         andi x20, x20, 0x3f8                      
                    la x22, data3                             
                    add x20, x20, x22                         
                    fld f6, 0(x20)                            
pfx.bb0.l7:         andi x20, x20, 0x3f8                      
                    la x21, data0                             
                    add x20, x20, x21                         
                    fld f7, 0(x20)                            
pfx.bb0.l8:         andi x22, x22, 0x3f8                      
                    la x20, data3                             
                    add x22, x22, x20                         
                    fld f8, 24(x22)                           
pfx.bb0.l9:         andi x19, x19, 0x3f8                      
                    la x21, data4                             
                    add x19, x19, x21                         
                    fld f9, 0(x19)                            
pfx.bb0.l10:        addi x18, zero, 852                       
pfx.bb0.l11:        addi x19, zero, 1824                      
pfx.bb0.l12:        addi x20, zero, 293                       
pfx.bb0.l13:        addi x21, zero, 839                       
pfx.bb0.l14:        addi x22, zero, 1940                      
pfx.bb0.l15:        addi x23, zero, 1796                      
pfx.bb0.l16:        addi x24, zero, 582                       
pfx.bb0.l17:        addi x25, zero, 359                       
pfx.bb0.l18:        addi x26, zero, 1839                      
pfx.bb0.l19:        addi x27, zero, 698                       
pfx.exit:


    /* TODO: Random setting for csrs */

    /* Used for mutation */
    li t5, 1

    /* Return to attacker */
    li a0, MSTATUS_MPP
    csrc mstatus, a0

#if COMMIT == VICTIM
  #if ATTACK == S2M || ATTACK == U2M
    li a0, MSTATUS_MPP
  #else // U2S
    li a0, (MSTATUS_MPP & (MSTATUS_MPP >> 1))
  #endif
    csrs mstatus, a0
#else // ATTACKER
  #if ATTACK == S2M
    li a0, (MSTATUS_MPP & (MSTATUS_MPP >> 1))
    csrs mstatus, a0
  #endif
#endif
    la t0, pre_attack0
    csrw mepc, t0
    mret

recv_end_m:
    cycle_end

    li gp, PASS
    li a1, CAUSE_SUPERVISOR_ECALL
    csrr t0, mcause
    beq a1, t0, 0f
    li gp, FAIL
0:  sim_exit

recv_end_s:
    cycle_end

    li gp, PASS
#if ATTACK == U2M || ATTACK == U2S
    li a1, CAUSE_USER_ECALL
    csrr t0, scause
    beq a1, t0, 0f
    li gp, FAIL
#endif
0:  sim_exit

xcpt:
    /* Disable external interrupt */
    li a0, MSTATUS_MPIE
    csrc mstatus, a0
    li a0, MIP_MEIP
    csrc mie, a0

    la a0, recv_end_m
    csrw mtvec, a0
    la a0, recv_end_s
    csrw stvec, a0

#if ISA == 1
    nop
    nop
    nop
#else
    plic_off
#endif

    cycle_start

    li a0, MSTATUS_MPP
    csrc mstatus, a0
#if ATTACK == S2M
    li a0, (MSTATUS_MPP & (MSTATUS_MPP >> 1))
    csrs mstatus, a0
#endif
    la t0, receive
    csrw mepc, t0
    mret

    .section ".tohost","aw",@progbits
    .align 6
    .global tohost
tohost:     .dword 0
    .align 6
    .global fromhost
fromhost:   .dword 0
    .align 6
    .global timing
timing:     .dword 0


    .section ".text.preattack0"
    .global pre_attack0
    .align 2
pre_attack0:
prp0:
prp0.entry:
prp0.entry.l0:      fle.s x21, f3, f4                         
prp0.entry.l1:      slt x22, x21, x19                         
prp0.entry.l2:      fmul.s f4, f2, f0, rdn                    
prp0.entry.l3:      slliw x18, x21, 1                         
prp0.entry.l4:      srliw x18, x19, 14                        
prp0.entry.l5:      la x22, prp0.bb2                          
                    jalr x18, 0(x22)                          
prp0.bb0:
prp0.bb0.l0:        flt.s x19, f4, f2                         
prp0.bb0.l1:        fsub.d f2, f3, f1, rmm                    
prp0.bb0.l2:        feq.s x21, f2, f4                         
prp0.bb0.l3:        fsub.s f1, f2, f3, dyn                    
prp0.bb0.l4:        fcvt.w.s x20, f3                          
prp0.bb0.l5:        bne x22, x21, prp0.bb3                    
prp0.bb1:
prp0.bb1.l0:        sltu x21, x19, x20                        
prp0.bb1.l1:        fcvt.d.w f1, x22                          
prp0.bb1.l2:        call fn1                                  
prp0.bb1.l3:        call fn1                                  
prp0.bb1.l4:        fmul.s f2, f0, f3, dyn                    
prp0.bb1.l5:        bne x18, x22, prp0.bb2                    
prp0.bb2:
prp0.bb2.l0:        la x19, prp0.bb3                          
                    jalr x20, 0(x19)                          
prp0.bb2.l1:        fclass.d x21, f2                          
prp0.bb2.l2:        call fn0                                  
prp0.bb2.l3:        call fn3                                  
prp0.bb2.l4:        srai x21, x22, 27                         
prp0.bb2.l5:        fcvt.s.w f2, x20                          
prp0.bb2.l6:        remu x22, x18, x21                        
prp0.bb2.l7:        flt.d x22, f2, f3                         
prp0.bb2.l8:        bltu x19, x20, prp0.bb3                   
prp0.bb3:
prp0.bb3.l0:        srai x18, x19, 10                         
prp0.bb3.l1:        flt.s x19, f3, f4                         
prp0.bb3.l2:        call fn0                                  
prp0.bb3.l3:        fmsub.s f0, f2, f3, f1, rne               
prp0.bb3.l4:        sll x22, x19, x18                         
prp0.bb3.l5:        bne x19, x22, prp0.exit                   
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      remu x19, x22, x18                        
prp1.entry.l1:      feq.s x20, f1, f2                         
prp1.entry.l2:      slt x20, x18, x22                         
prp1.entry.l3:      fdiv.s f0, f3, f1, rmm                    
prp1.entry.l4:      fcvt.wu.s x20, f3                         
prp1.entry.l5:      call fn1                                  
prp1.entry.l6:      fence.i                                   
prp1.entry.l7:      fcvt.w.s x22, f1                          
prp1.entry.l8:      srai x18, x20, 59                         
prp1.entry.l9:      fle.d x19, f3, f2                         
prp1.entry.l10:     bltu x22, x19, prp1.bb2                   
prp1.bb0:
prp1.bb0.l0:        fsgnjx.d f3, f2, f1                       
prp1.bb0.l1:        fmv.d.x f2, x21                           
prp1.bb0.l2:        fmsub.s f1, f2, f0, f3, rdn               
prp1.bb0.l3:        beq x18, x19, prp1.bb2                    
prp1.bb0.l4:        fcvt.wu.s x22, f1                         
prp1.bb0.l5:        fnmsub.d f4, f0, f3, f2, dyn              
prp1.bb0.l6:        fle.s x21, f1, f3                         
prp1.bb0.l7:        fle.d x19, f4, f0                         
prp1.bb0.l8:        la x22, prp1.bb2                          
                    jalr x20, 0(x22)                          
prp1.bb1:
prp1.bb1.l0:        srli x22, x18, 24                         
prp1.bb1.l1:        fsgnjn.s f2, f3, f1                       
prp1.bb1.l2:        fcvt.s.l f3, x19                          
prp1.bb1.l3:        lui x18, 811                              
prp1.bb1.l4:        sltu x20, x22, x19                        
prp1.bb1.l5:        bne x18, x19, prp1.bb2                    
prp1.bb2:
prp1.bb2.l0:        fcvt.d.wu f4, x19                         
prp1.bb2.l1:        fcvt.s.w f1, x18                          
prp1.bb2.l2:        fsqrt.d f4, f0, rtz                       
prp1.bb2.l3:        fcvt.l.d x19, f4                          
prp1.bb2.l4:        fcvt.lu.d x20, f0                         
prp1.bb2.l5:        fcvt.s.lu f3, x22                         
prp1.bb2.l6:        lui x20, 3589                             
prp1.bb2.l7:        fmv.x.w x21, f1                           
prp1.bb2.l8:        fclass.d x18, f0                          
prp1.bb2.l9:        fcvt.lu.d x19, f3                         
prp1.bb2.l10:       la x20, prp1.exit                         
                    jalr x19, 0(x20)                          
prp1.bb3:
prp1.bb3.l0:        fmul.s f0, f1, f2, dyn                    
prp1.bb3.l1:        add x20, x22, x21                         
prp1.bb3.l2:        fmax.d f4, f0, f1                         
prp1.bb3.l3:        call fn1                                  
prp1.bb3.l4:        auipc x22, 3892                           
prp1.bb3.l5:        la x20, prp1.exit                         
                    jalr x22, 0(x20)                          
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        fsqrt.d f4, f1, rdn                       
tc.entry.l1:        fcvt.wu.d x22, f3                         
tc.entry.l2:        call fn4                                  
tc.entry.l3:        andi x18, x18, 0x3f8                      
                    la x22, data3                             
                    add x18, x18, x22                         
                    amomin.d x19, x21, (x18)                  
tc.entry.l4:        call fn3                                  
tc.entry.l5:        andi x20, x20, 0x3f8                      
                    la x21, data7                             
                    add x20, x20, x21                         
                    lh x22, 28(x20)                           
tc.entry.l6:        fsgnj.d f2, f3, f0                        
tc.entry.l7:        bltu x20, x22, tc.bb3                     
tc.bb0:
tc.bb0.l0:          fcvt.wu.s x19, f3                         
tc.bb0.l1:          fcvt.d.s f0, f0                           
tc.bb0.l2:          div x22, x18, x20                         
tc.bb0.l3:          call fn1                                  
tc.bb0.l4:          fcvt.s.w f2, x19                          
tc.bb0.l5:          fmsub.d f1, f2, f3, f4, rne               
tc.bb0.l6:          fmin.s f4, f0, f1                         
tc.bb0.l7:          blt x21, x18, tc.bb1                      
tc.bb0.l8:          fcvt.lu.s x19, f0                         
tc.bb0.l9:          jal x21, tc.bb1                           
tc.bb1:
tc.bb1.l0:          remu x19, x18, x21                        
tc.bb1.l1:          remw x20, x19, x22                        
tc.bb1.l2:          fsub.s f4, f3, f0, rdn                    
tc.bb1.l3:          call fn4                                  
tc.bb1.l4:          fsgnjx.s f4, f2, f3                       
tc.bb1.l5:          andi x18, x18, 0x3f8                      
                    la x22, data1                             
                    add x18, x18, x22                         
                    amoxor.w x19, x20, (x18)                  
tc.bb1.l6:          bne x18, x21, tc.bb2                      
tc.bb2:
tc.bb2.l0:          fsgnjn.d f0, f4, f3                       
tc.bb2.l1:          andi x21, x21, 0x3f8                      
                    la x18, data3                             
                    add x21, x21, x18                         
                    amoadd.w x19, x20, (x21)                  
tc.bb2.l2:          andi x20, x20, 0x3f8                      
                    la x21, data3                             
                    add x20, x20, x21                         
                    lr.d x18, (x20)                           
tc.bb2.l3:          call fn0                                  
tc.bb2.l4:          sub x22, x21, x18                         
tc.bb2.l5:          bne x22, x21, tc.exit                     
tc.bb3:
tc.bb3.l0:          fmul.s f3, f0, f1, rmm                    
tc.bb3.l1:          andi x22, x22, 0x3f8                      
                    la x20, data5                             
                    add x22, x22, x20                         
                    amominu.w x21, x19, (x22)                 
tc.bb3.l2:          call fn1                                  
tc.bb3.l3:          andi x20, x20, 0x3f8                      
                    la x22, data1                             
                    add x20, x20, x22                         
                    ld x19, 0(x20)                            
tc.bb3.l4:          fnmsub.s f1, f2, f3, f4, rne              
tc.bb3.l5:          lui x20, 3007                             
tc.bb3.l6:          fcvt.d.l f4, x19                          
tc.bb3.l7:          bgeu x20, x18, tc.exit                    
tc.exit:
attack_end:
#if ATTACK == S2M
  #if COMMIT == VICTIM
    la t0, mtvec_handler
  #else // ATTACK
    la t0, stvec_handler
  #endif // COMMIT
    jr t0
#elif ATTACK == U2M
  #if COMMIT == VICTIM
    la t0, mtvec_handler
    jr t0
  #else // ATTACK
    ecall
  #endif // COMMIT
#else // U2S
  #if COMMIT == VICTIM
    la t0, stvec_handler
    jr t0
  #else // ATTACK
    ecall
  #endif // COMMIT
#endif // ATTACK

    .align 6
    .global spdoc
spdoc:      .dword 0


    .global shared
    .align 12
shared:
fn0:
fn0.entry:
fn0.entry.l0:       addi x24, x27, 1064                       
fn0.entry.l1:       lui x24, 1136                             
fn0.entry.l2:       remuw x23, x26, x24                       
fn0.entry.l3:       fmv.x.w x23, f8                           
fn0.entry.l4:       fadd.d f6, f8, f5, rmm                    
fn0.entry.l5:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       sll x25, x23, x24                         
fn1.entry.l1:       fcvt.w.d x26, f9                          
fn1.entry.l2:       and x24, x23, x27                         
fn1.entry.l3:       slli x24, x26, 27                         
fn1.entry.l4:       fsgnjx.d f9, f5, f6                       
fn1.entry.l5:       flt.s x26, f9, f7                         
fn1.entry.l6:       fcvt.d.lu f5, x26                         
fn1.entry.l7:       fcvt.w.d x27, f5                          
fn1.entry.l8:       fmax.s f8, f9, f5                         
fn1.entry.l9:       fmv.d.x f8, x24                           
fn1.entry.l10:      ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       srl x27, x25, x24                         
fn2.entry.l1:       fle.s x25, f7, f6                         
fn2.entry.l2:       sltu x23, x26, x27                        
fn2.entry.l3:       fcvt.s.w f6, x27                          
fn2.entry.l4:       sra x26, x23, x24                         
fn2.entry.l5:       fmv.x.w x26, f6                           
fn2.entry.l6:       mulhu x23, x26, x27                       
fn2.entry.l7:       fsub.s f9, f7, f8, rtz                    
fn2.entry.l8:       flt.d x25, f6, f9                         
fn2.entry.l9:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       mulhu x25, x24, x26                       
fn3.entry.l1:       slti x26, x23, 448                        
fn3.entry.l2:       flt.d x23, f9, f8                         
fn3.entry.l3:       remu x25, x26, x27                        
fn3.entry.l4:       sraiw x25, x27, 26                        
fn3.entry.l5:       remu x27, x26, x25                        
fn3.entry.l6:       ret                                       
fn3.exit:
fn4:
.align 8
fn4.entry:
fn4.entry.l0:       feq.d x23, f8, f7                         
fn4.entry.l1:       fmv.w.x f9, x23                           
fn4.entry.l2:       remuw x25, x26, x23                       
fn4.entry.l3:       fcvt.lu.s x27, f5                         
fn4.entry.l4:       fcvt.d.w f7, x26                          
fn4.entry.l5:       ret                                       
fn4.exit:
shared_end:


    .section ".text.receive","ax",@progbits
    .global receive
    .align 2
receive:
receive_end:
    ecall


    .section ".data","aw",@progbits
    .global data
data:
    .align 12
data0:
    .dword 0xf6c556bcf5a87da9, 0xe063ce140a3de00a
    .dword 0x49b5a9da1716e3d7, 0xa0bb918e3fd36ff9
    .dword 0xd4e217d637d8e08b, 0x27e2cc5ecb3e80e8
    .dword 0x3498ec781270e932, 0xba83daa709d3511
    .dword 0xebf6d398c10d5713, 0xd07c69426caf6b78
    .dword 0x4cc9e238437333a6, 0xec71a78e35710946
    .dword 0x35c75c0dc2be1f9b, 0x21c97d0896a0dce
    .dword 0xcda15a06633e3f70, 0x304a41f5af9f87f2
    .dword 0x336fcafbf2705f14, 0xd810bf860edb2254
    .dword 0x87df6515bef2e577, 0xd1106a9b2e8d2d66
    .dword 0x8b8990308483db68, 0x716c1621c38aebe8
    .dword 0xa2e6bc69c1bb5efc, 0xc7fcab66c345788b
    .dword 0x7ef5ed0508548ed2, 0x2ab13ce1ce7dc0b6
    .dword 0xccc54eb138ad50df, 0x8e8c3e27caa599cf
    .dword 0x4e80df8a0903f63e, 0xc68c555d6f0327be
    .dword 0x36d81dd54944dc34, 0xff3e2562ce5d410f
    .dword 0x265a23f6cc465634, 0xf5c9b06f755ae2ae
    .dword 0x5385d06dacd3e1c0, 0xaaa646ab0120ea3a
    .dword 0x52f850a52e03ed2c, 0x2e26a987c8e6a37b
    .dword 0x4ebb240327d5c395, 0x7dc7f80fb7b4705c
    .dword 0xe4ff5e8904135ee, 0x4a79377908c9b5c0
    .dword 0x81c2cf3e8adeab09, 0x7b9e0b529dda15e4
    .dword 0xd73971c1a7737f92, 0xfe4fb1b7aa1c8e53
    .dword 0x339cbaaf34cbe01f, 0xcf343856373a289a
    .dword 0xbb5b99eafed752c8, 0x838e35322904ef8
    .dword 0xfe2fb0c1fee5026, 0xbb25c0f4bb80b0ec
    .dword 0x5bd26889afb4c01d, 0x1848388a1b388777
    .dword 0x1d0dbe21d31190b1, 0x7acee2608f4bc23d
    .dword 0xbc05395a681ab27, 0xb51323f5871a0468
    .dword 0xa53db127373c3e4c, 0xbdd8da7b8b6cc6c6
    .dword 0x8153b0ae0b6da42d, 0xbc94db2fdc05cc19
    .dword 0x3b745457e4e2c36b, 0x3f0e2118a707efe3
    .dword 0x8119ddae5d6ff4bb, 0xa956697922db49e2
    .dword 0x6eb7b0fb14ab5a4a, 0x55a5b4eb960ab5ee
    .dword 0x2df30deae92ff2e2, 0x30e23a22cdc3b7cf
    .dword 0x8bd1e3548ec5c16, 0x9c76ab20f6e0d7f7
    .dword 0x5aa10676b9b47efd, 0x1a711c6b1ac277ab
    .dword 0x2e2092f1a6252a24, 0x552225b8e55c8620
    .dword 0xe10c733fe4f3f065, 0x298734097c821a35
    .dword 0x612b2177fa5700ac, 0x9c260019b4586fc5
    .dword 0x34c9141647b78985, 0x81c0420c89e6a9a2
    .dword 0x8e19d527fa06a4da, 0x4d0b94724d32e988
    .dword 0x6a91ec0f0c5e1150, 0x55a1fe021136befa
    .dword 0x26876e2b6dd606f1, 0x9babc51107b5c85e
    .dword 0xd1a70e0db9bc9cd2, 0x52c45f7a6478db70
    .dword 0x95121f19bd353236, 0x9a1634b842ce60f
    .dword 0x8f319977b300ec25, 0xebaa5bc917dd5db2
    .dword 0x2ed3d4b504d24c46, 0xe7a7783333887cfa
    .dword 0xf3aa9c8b03090ce4, 0x6ab3053e33ef4513
    .dword 0x97f6c3ee9abddd8d, 0x5531e9fb16468304
    .dword 0x439b271abc65f99e, 0x1b822fa41adcb18a
    .dword 0x5d0940360e26d3de, 0xb9945c3515bd7e28
    .dword 0xdb48269b0604cd60, 0xd5279498a6119440
    .dword 0xa9d9fc9cec704d40, 0x4230373d8cc2574a
    .dword 0x1745dda826f1d3c7, 0x73964cca636cc91c
    .dword 0xb37ce706f9dc0f08, 0xf9eb226aa4134d37
    .dword 0xd63ba89111ec6b5a, 0xd19072a1b1ae238c
    .dword 0xfd13196374820506, 0x2eee28f90118497
    .dword 0x604cce56eafb0e27, 0x16a2f54036b0aa0b
    .dword 0xdf5e919cb5b7f6e8, 0x5484fadfc8f52c18
    .dword 0x32d5ee4b986ae15a, 0xb000065bc8c3e30a
    .dword 0xa1c098fafeba55e5, 0x3e01cc6393c1aa35
    .dword 0xf5b3a1a9b83306b3, 0xb17edbd453ded024
    .dword 0x422021049c78f9cd, 0xfc3492e60a43c601

    .align 12
data1:
    .dword 0x6de55be6d7265611, 0x10dc14894804c689
    .dword 0x40a514ae6ce6c6cc, 0x1d83c53de706e4
    .dword 0xba67d462430e4bf9, 0xfd2116377a9ef0a6
    .dword 0x538735aece8d06fe, 0x22ae4f3478c0abad
    .dword 0x8c917ee576227ac4, 0x55a8db9620c8c83c
    .dword 0xc32e5f0256ec7397, 0x643a2fa0162b347e
    .dword 0x8cccf50355c8d0ad, 0x373e2cb13823f253
    .dword 0xae1299fe1cae3d8d, 0x7b9058593caf3707
    .dword 0xdccf2d3d87263282, 0xcfff497fb4deb18f
    .dword 0xb40d7a4745960a03, 0xb7a87f7042c5fde6
    .dword 0x7111996dbb71fc2a, 0x149eb098fff3c948
    .dword 0xfb2ff65823b846c3, 0x7603dbedf637bab0
    .dword 0xdca2bf2e2f4fa4d2, 0x18ce566bbb0f7efd
    .dword 0x383d667d8aa2f700, 0x73e0cb2d87659d76
    .dword 0x6df7685b17232eee, 0x4c840105d6059ecd
    .dword 0xf4c3dfb1b0c3092f, 0x4b49c1aa192ea773
    .dword 0xa82530467667f499, 0x4cce0f8d6437b9ae
    .dword 0x61003506ee858bc4, 0x3b73b019f900e3f3
    .dword 0x75442fc2c6551d64, 0xa2f7d7ca726e8b65
    .dword 0xc58892d4de739d18, 0xef8252da21cc07d9
    .dword 0xc17be43f19aa2788, 0x9b47d69910a859b0
    .dword 0x874d322c9a90894d, 0x58d4970a17a0ef80
    .dword 0xc42286390d5d25b6, 0xd6757633da2397f9
    .dword 0x5dfc1d3525a31aca, 0x6c08b78a03c2f45c
    .dword 0xb7b2072ee5bf2447, 0x7d5c90e6272ae1ca
    .dword 0x48d1a4f2c12f7024, 0x6da71555f0cb8f55
    .dword 0x121364c0a1feffc2, 0x49e57200b3e043ec
    .dword 0xd151ed6d979b4651, 0xee97a0baa928e631
    .dword 0xc49c4d6e23b02f53, 0xa2300754c1f93507
    .dword 0x131a246c082128af, 0x71f5e92fb790c4fb
    .dword 0xb665362caa9920bc, 0x48bf55e21501ec06
    .dword 0xba9505d6f74f014f, 0xd297e953889b67cb
    .dword 0xf4ae8ff3fef0b518, 0xdc57a3441e5fed93
    .dword 0x904e7a66e2970f52, 0x40f7dbab1bdbeffc
    .dword 0x55dd6b4b4546a27e, 0x6b91ac6aef8fd95b
    .dword 0x4885203bc30c7c17, 0xc5290d135f87360d
    .dword 0x190e54e208928f52, 0x60c5d6b7e5dc07a9
    .dword 0x84fa61b0d591596b, 0x7a07a6f79bb3aacc
    .dword 0xeb0310613bc812c3, 0x9eb7859d7854b5b2
    .dword 0xce40366f73af17dc, 0xc660e91008abf5b3
    .dword 0x404bf6c10ed18dce, 0xbb5dfb7ef11aca0d
    .dword 0xb2620ba6739bfccd, 0x3c39dc167961bda1
    .dword 0xa4734fc875c80032, 0x293b4970d35ad68b
    .dword 0x73cdfbf9d856b853, 0x968ca10044dea38e
    .dword 0xe2ee054bbae1f8a8, 0xd3add5e9de5ce4d1
    .dword 0x4ba10c2de3b06f0c, 0xe06dfcab9aca7b16
    .dword 0xaaa2d44ee43db316, 0x648f57f896351bfc
    .dword 0x842038db19c89e4a, 0x7ff898371c783ab0
    .dword 0xbefa3430981dd191, 0xe964e7396c7a8c1a
    .dword 0x127963dcfc6ad41c, 0x1738321a1aa7b877
    .dword 0x783383788b34d0e7, 0x3afe1c91e4e866f9
    .dword 0xbf2418bf9ef6883, 0xfd9d91703f3dc9ba
    .dword 0x4822e7414d600d6c, 0xdfff41ef12986e4b
    .dword 0x34f4334172b01a9, 0x6bd3f7a2d08a9740
    .dword 0x6d8a84776396c7d9, 0xf1ad2a9d99fb5de
    .dword 0x281037622ae2f773, 0x3ade93815b05e864
    .dword 0x5eeb264fe51b17f1, 0x2c2b5211dd2d8468
    .dword 0xdb8050207238289b, 0x76b6f5c10cd203d6
    .dword 0x55f26cbe3d7c580d, 0xdf212eba44f291f
    .dword 0x74f1e7b0d5c3397f, 0x2e7ee7577dfb8f60
    .dword 0x7e235e28fe41c263, 0x9d93376104564ef3
    .dword 0xfa60b330fbe7d821, 0x6f6e3b5fb3115757
    .dword 0xbc02cc0e5c5fe51f, 0x402e2737313bc2b6
    .dword 0x3c4b9908f4ff4f46, 0x13b61a196372842e

    .align 12
data2:
    .dword 0xe41b6e6605d8e09c, 0x9db4430db1e2080b
    .dword 0x46199fe68a6b3d31, 0xb68d4e8db626e91b
    .dword 0xa5851d7c8034b975, 0xc13949b529a5672a
    .dword 0x8e312c5fce6771f, 0xfbbdc3e9b130e60a
    .dword 0x7f2d108e86cb22b9, 0x8baa363bba53ec6f
    .dword 0x677aba90db9b71e3, 0xb5a138aa602c037a
    .dword 0xedd7b1fa263f2eb6, 0x5d88d6c7771994f3
    .dword 0x6fdbce51da54d195, 0x3489f063ac43f68a
    .dword 0x3eea4d8f4a7f1610, 0xf3f1a51d1a49a667
    .dword 0x52547bc358369cbd, 0x6849e4182677f319
    .dword 0xb23a1d3956a3cc13, 0xb88c469d7a23d9d8
    .dword 0x6175b205f5343e73, 0xaa34474b203cfc84
    .dword 0x300e05ac8746f05c, 0x93e7d1789ff8f593
    .dword 0xb1f425c66e1a2db9, 0x5d8d6d06409296e9
    .dword 0x4e8bfee0d79c74bf, 0xa76884a008404178
    .dword 0x1f998bfad3f4b040, 0x7f0c953ee0aaf269
    .dword 0x31d46a00b97029bc, 0x4a39efd555553297
    .dword 0xc01e22797722d31f, 0xcfd1bd2b33c65bbe
    .dword 0xef2e1a2be5d51604, 0x9530f5e3b504a8cc
    .dword 0x4959fad1a0d1f33f, 0x59453f765ddc6
    .dword 0xb7e7535a0b936075, 0xe65d1fe3291a26bf
    .dword 0x9fa46266093e71e7, 0x629f9136c5566f16
    .dword 0x95da7ec69baf83c2, 0x92bda14fa5c0c99a
    .dword 0x37c6cd65fdc48fb5, 0xd2f3197ea0353c08
    .dword 0x7dad17fc8934abb1, 0xa8c45a5c2fb33dad
    .dword 0xcfcfca2df2812144, 0x7b23b5292167e1c8
    .dword 0x82d1ad7e45018c0a, 0x87e3b978f73a2a20
    .dword 0xc8862ba0d2eff013, 0x721fda33b9bae001
    .dword 0xbcd15354581f254e, 0xb360c5e877ec6484
    .dword 0xd0d3482c6a1461aa, 0x8d819d63e35bca
    .dword 0xce57577fb03a0b59, 0x256954f558c9c8fe
    .dword 0x12e138ded482bb49, 0xca575f3374625fdc
    .dword 0x273fdf73be045d04, 0x4c83a07f3a96fda4
    .dword 0xb0a6375fcd6be76f, 0x5531d261b1fa668f
    .dword 0x60e6e917ed5c6b92, 0x462164daa6ead422
    .dword 0xc726ff8deaf072c9, 0x15f8463a87b486ca
    .dword 0x9f855c68ea85a64d, 0xed4656f2585d7ed1
    .dword 0x78f915064082051d, 0x3945eb857d5f9290
    .dword 0x57a06f6647892166, 0xab256c7f8e4affc1
    .dword 0x76c0213569933d9e, 0x932c374be065bbf1
    .dword 0xa521ae245969d860, 0xd7403108a8e75aae
    .dword 0xc47b8a2d81ce5c7d, 0xac28fe83313d08e5
    .dword 0xbd0106d03b3a9afa, 0x3872e154251e85
    .dword 0x2484bf81fe88d68f, 0xd90c8910915322ab
    .dword 0xe1e2f16a82b44655, 0x5de321c3acfca4d4
    .dword 0xe6409cac0ad9a774, 0x1169d4a3ca19c570
    .dword 0xb044026dd38bc08f, 0x583e88c4264a2039
    .dword 0x49ef1a0f8c7e8187, 0x91b8db75c9977509
    .dword 0x4e45b3546a0220ee, 0x92ba6e1a7909606c
    .dword 0xe8f090f3058d0f7f, 0x2e9ec47994d91a0b
    .dword 0x985a5f354575bf0b, 0x74ebb46a408ee0d3
    .dword 0xe34545ebb242b044, 0xd3a8b76fd8dcc35
    .dword 0xb8da5b1131cf82c9, 0x25296197320299a7
    .dword 0x1456aafd6743274, 0x5e2ca786ad7cd685
    .dword 0xe6bdb1654786215b, 0xedd2367c634485aa
    .dword 0x7affeac6997d7543, 0x22a8086dd5bec62f
    .dword 0x66e863147bfb939f, 0xbd701910eefb5ece
    .dword 0xb1589f7c0e4f0a1f, 0xc56e6de6eda1c56
    .dword 0xbb7c0211086824c4, 0xd79505a92fe3fb25
    .dword 0x8aab3429ee2ff526, 0xb3afc769ab76c8ff
    .dword 0xaef47cfd7c12ed00, 0xeaac37eb9fd4cad4
    .dword 0x3e13f2257e4dfa75, 0xfcd2666c7615f275
    .dword 0x99bb5b3105d991c7, 0xc0a86b365e9d95be
    .dword 0x96845b8299a1bbf5, 0x447687ee15106da1

    .align 12
data3:
    .dword 0xcf34eda2c7392cbf, 0x57957cf6793563c2
    .dword 0x4bf2c655a31343cc, 0x89b09f81dcca96c9
    .dword 0x48341dc787092154, 0x9cd2f7515fd071ba
    .dword 0xdcb82ad628ad93a5, 0xf5e399e2308940fc
    .dword 0x679ea591ce4b041a, 0xc32c844330f76fec
    .dword 0x903e96add0c30c7a, 0x7f80846f83ad0f1d
    .dword 0x5593ba2814b80ef2, 0x4cb7b0feb2c32d01
    .dword 0x85201b0f075a13b0, 0xf28d0afe4df47dc8
    .dword 0xaf667764b14a120c, 0xcfba6f63f6aae168
    .dword 0xb57983ec8c96d30, 0x68f0ea2163f999c4
    .dword 0x6c3b9e162d5dbb63, 0xd5d9e7ec78d9d3ae
    .dword 0xe8dd0235e8882d79, 0x724da1c3d4bc4ed8
    .dword 0xeb875064e154f784, 0xfbbe6b6a78a199d2
    .dword 0xcddbcdaa82b1087a, 0xd7354a6ecc2f8650
    .dword 0x591d63ec6fd5eefc, 0xcc0e70c43db322e4
    .dword 0x6a11b803428dd33, 0x488fd5f3d5109d56
    .dword 0xbda475e4bd7e4a15, 0xb2066bda7085c25f
    .dword 0xfbd41e93b8416d2e, 0xdee3bb769153d2f6
    .dword 0x1066e9b8052b7713, 0x6d8ffec89dd9c337
    .dword 0x74f5fa0df2dc4117, 0xfe994adba6ac02e7
    .dword 0xe31c6f5436cdd0b0, 0x2c492798298f196e
    .dword 0x364cf3bdcfb46585, 0x60ded8ba792372b2
    .dword 0x194d64efe4ca35ce, 0x5b34636d11f812ca
    .dword 0xb0af6a163747f255, 0x801e13b3e0074251
    .dword 0xe5ce37778b798610, 0xe8310160dd79d6ef
    .dword 0x6cc0786695e1ebd, 0xee29199415f9e71e
    .dword 0xdf4efd0306f903e5, 0x801863266bd5c53e
    .dword 0xfdfde7a4d4dc0c99, 0x9ea9f8216dc783f8
    .dword 0x700b8ccd5c622dd2, 0x6d33513a4401aba9
    .dword 0xbdf67fdac70c95ae, 0x9f5d19197504e926
    .dword 0x52d52e62fabb780c, 0xbc94bdab2b5d884b
    .dword 0x57a06a94d44737bc, 0x7a113c1758a42336
    .dword 0xe6cc215e7df04026, 0x37b5a19c30289035
    .dword 0xf674f5ad3c16ea54, 0x29533d21eabc4800
    .dword 0xbbd9c10f957821fe, 0xbe175e1dba0d150d
    .dword 0xcc28d1e888a2f826, 0x8d09b54d4d78606b
    .dword 0x94f71a9e02cfdbc5, 0x571b2051c0d4bce
    .dword 0x798abe99a577384a, 0x26828cca9192ce92
    .dword 0x2e8da00dc7ecdec7, 0x694343df198798ef
    .dword 0xc5686850cb4ea4c1, 0x996b614fead73749
    .dword 0xe407f11388a8e8e6, 0x84837c7aee181ae2
    .dword 0xe4df33d0057e6b41, 0xa193314041ac49d
    .dword 0x5b6c446c9771a868, 0x54fa66cb5d0b3cf5
    .dword 0xacb4cd017f06b2f9, 0x4b42de1c86ec6134
    .dword 0x37dee6a6b29fb8a1, 0x1f31a2d78cdd776d
    .dword 0x95042522381bd065, 0xbb90408dab9cafb8
    .dword 0xf465e7d2ce5af772, 0xb6173b65b669ab1a
    .dword 0xca00b961d4e87427, 0x570b59fc97d5ffec
    .dword 0x775752cb23de5bd9, 0x3dec32593d43147c
    .dword 0x4b138aaa99ea5295, 0x99923bb841dd9639
    .dword 0xbef53c0cd5c271a9, 0x71788739fbaaa152
    .dword 0x43984412b4bcb46d, 0x7dce2001bf316a45
    .dword 0xe8daa6f875a0a29f, 0x778bbcebb6bc993
    .dword 0x92474b2ab1b92d55, 0xeead33996842f0c0
    .dword 0xd2037c1681670e8, 0x12b1a859dd3e7791
    .dword 0x71a6ae50af46ac9c, 0x6c78c1b528872889
    .dword 0xa0ad8f481645a4d, 0x1fbbce5ce2dafb83
    .dword 0x442094ba612d2928, 0xd5cc272501571f10
    .dword 0x4ab15e5d20341447, 0xe9f150f3e86627be
    .dword 0x68d322181aa9f6d4, 0x258ea07bdc1d79c5
    .dword 0xf6d29324b2adb957, 0x1a87e5f49c9c6bf3
    .dword 0xa792f06fb01e1dea, 0x1f4a401b2cd49052
    .dword 0xd6ddfacda2fe1e2d, 0x605f6701bbb342a5
    .dword 0xf1a2ad48aa205ab7, 0xd4e7cbb42b2c760b

    .align 12
data4:
    .dword 0x572a1e45c7cd74d8, 0xa2f2670ddc7607f
    .dword 0xea2c72f5c781b147, 0x34e6e53bdcfa477e
    .dword 0xbaabfba2faeb3e26, 0x80909b3a7428f401
    .dword 0x4ec28e8d18925578, 0xac1ab4dc014b5413
    .dword 0xb05fff4ced7e49f1, 0x552281074a5bdc8c
    .dword 0xe7c7310b7b0c290f, 0xfad3ab4904b540d0
    .dword 0x9704ca63b2191c75, 0x45422d3cb53bf2ed
    .dword 0x3a347044ec0f47bb, 0x6b1792f393cd0690
    .dword 0xb38442162f1aa7a7, 0x7f23e121662c8ed3
    .dword 0xf72e5e8596223022, 0xe83bf83245cce88f
    .dword 0x7a723b53ccef076f, 0xab2a923a667e9a81
    .dword 0x83902f3d2850e90d, 0xeec9fbb5c6dc1c3d
    .dword 0x8d865862ca76b369, 0x9a67e11e50889b89
    .dword 0x23fea1609373329e, 0x42ca520349f12e7d
    .dword 0x27c56045d60d7810, 0x4980039013ac677c
    .dword 0xb12e7a7098795405, 0x35c2cb750aff7038
    .dword 0xe4fc46113dbd6bf0, 0xd8b589db0d1fe2cc
    .dword 0xa7e9b2629bdf00cc, 0x92ae281260ff390b
    .dword 0x9dad175f0cae8c04, 0xc81bfada8394e331
    .dword 0xc8962aee3b9ef166, 0x54b41e14b2f93d71
    .dword 0xce64c4c2147f7077, 0xb1aa1cf068e72fd0
    .dword 0x6a01aa5ed1edd067, 0x4bd0ba844c8ae14c
    .dword 0xbcf806990b6f6828, 0xc67b8b53d1594ae2
    .dword 0x1d2d2541c32fce03, 0xa3533db9e57002a4
    .dword 0xba32e77e21229e17, 0x8fbe4a8b89e92a8d
    .dword 0x9d8e82a641f6217e, 0x704ba1ac9c4265fc
    .dword 0xd854dc78d7f14b95, 0x7f8c874d1772147c
    .dword 0xdd483080d5350739, 0x21901f5671dff60f
    .dword 0xb4f2eb5711d867ad, 0xdcf2c586f5949e65
    .dword 0x6310f61d3dd1110e, 0x5d57d078f574b314
    .dword 0xea7d5a73eadd948e, 0x1a55ccb1a8d75390
    .dword 0xa2a1de29cfad8382, 0xeb10c8f2a0691a6b
    .dword 0x122fd393e5c43000, 0x330e3856bc544ffa
    .dword 0xe84f146730198d0e, 0x6ab8b2ce70540966
    .dword 0xb3a9d9689b32d504, 0xfcb46d15f27f78b5
    .dword 0x429c4155adfa77e1, 0x8d5009aa18a47009
    .dword 0x697fefc9975c535a, 0x7ee66ea983d9e75e
    .dword 0x7a551dc528906724, 0xfbfd3be4a79ca02
    .dword 0x939fb02b1883d78d, 0x6c0388b02ac019e4
    .dword 0xab86aad1368044ea, 0xf1741b996c52a417
    .dword 0x915ca56f430a2746, 0x7731ef79cea67a79
    .dword 0x66368ddf39f594ac, 0xc2110b0f70f0d62f
    .dword 0xbad1a63eda118bc1, 0xd2871643c09e7684
    .dword 0xcf0c0445558ab93e, 0x2d7fdfaf9010f39
    .dword 0x527b0203787b582c, 0x69f4e77481f65504
    .dword 0x330e49891993333e, 0xe41acc6d3d39adf6
    .dword 0xd24d59e68810e71a, 0x838d76ce76465fec
    .dword 0x7d98facc7b50da0a, 0x805cbddd37fa84e4
    .dword 0x5669e1437ed565ad, 0x83f1b030a460c35a
    .dword 0x544774ffe83f8b0a, 0x5832e1ee55a5dc45
    .dword 0x2ab6e3a03d6e9dcf, 0xbaa26c3e7ba45859
    .dword 0xa5ec5e1fb806fe91, 0xf719b78d421086ea
    .dword 0xeb32c8ec2432dd3d, 0x8739ce948935a269
    .dword 0x7b15d543411cde8, 0xbe6bc3c3291806fb
    .dword 0xa5ec7b661bd1588b, 0x69bb4dd29d6b56
    .dword 0x9555867af10bad03, 0xa72b582b168e3d9e
    .dword 0xd81ce02722e11714, 0x87890c8b28f079d1
    .dword 0x204609f0122b05e0, 0x80ffddda38773dbd
    .dword 0x37c2e00e95764186, 0x8897cd18f8198a3f
    .dword 0x50da2ae072e66b7, 0xf636d6cd3fa80185
    .dword 0xa42b58f1e782dac1, 0xe168110817a08eb5
    .dword 0x216b060fa0b52f7c, 0xf74289d7f4318a2d
    .dword 0x15d9e1760d21300, 0x2554f029d3bc58de
    .dword 0x9483dd916df5f09, 0x4fb8275a87ad2c59

    .align 12
data5:
    .dword 0x6ce8fabe6f50c0d4, 0x2fc1474bbf98e526
    .dword 0xc1234be6d4c39c3c, 0xaa976d5244598a24
    .dword 0xad3149e33d71d8d0, 0xb1783a3cc9669453
    .dword 0x1002fc91f22f7f2c, 0xf87820ba22da2977
    .dword 0x6a296802033c4835, 0x9f7260a803987f69
    .dword 0xb1d321842ba6cab5, 0x7c61ddb6186c98ce
    .dword 0xc84aa7ca9f2fae7c, 0xf4df0bc21be50022
    .dword 0xd0fd46722b768ae7, 0x80f06515676edd11
    .dword 0xb6ff4574fea2c4c1, 0x64d0ca50afe7c3f5
    .dword 0xce87914d16fb0ab0, 0x6a32a009d650caad
    .dword 0x5534ce8f70890e4f, 0xe05a4fbcb96d7e82
    .dword 0x1c52f66097f44c65, 0xd678b666e0870644
    .dword 0x86a885f3b0e07b5c, 0x4366b46741594a56
    .dword 0x1e4197191e83863d, 0xc34a6224fc481cf1
    .dword 0x783a41861dbf3163, 0x2f42be7e47f784a4
    .dword 0x9433bd8093df30ca, 0x9b3a72ba83c29f61
    .dword 0x6e78c021b7e8bfe9, 0x4da0edb5d74909f4
    .dword 0xa574510226bfa1f7, 0x3b9b1133cea4014f
    .dword 0xb314c3c5d159339c, 0x69c36f978a1995aa
    .dword 0x284c76c649e4f9fd, 0x5e438f6ad1d2c59c
    .dword 0x99ab41639c0a3bd9, 0xb3148ae1aa4b728d
    .dword 0x90d1bb2784b85f1b, 0xea7e4e7307bd387f
    .dword 0xea0dd87227f53c8, 0x31886241aa7bab48
    .dword 0x1031d2193ed4a1ef, 0x888b7dd90bc6bc0b
    .dword 0xad9da6ffcccd489a, 0xbab54ba1de2b67e6
    .dword 0x3f0898614b1ca799, 0x24cfb6bbf4d04749
    .dword 0x146dac0a3824873e, 0x6bb6c3b39bb6d75a
    .dword 0x173a3ebcf787b135, 0x61fc38f869d71f1b
    .dword 0xb51e46a12daaf75, 0x6deaf1404efb84ac
    .dword 0x7d6875b4b38da757, 0x9d6b3164e10dad96
    .dword 0x47124c913d8da675, 0xadd40327e4b0610
    .dword 0x9860926e215ab57a, 0x58dc5f5d134d0d62
    .dword 0xe95866c1597d825a, 0x48bc9a224dc0df4e
    .dword 0xcedcb919f723be41, 0xd99437f6c8d98d6e
    .dword 0xb5846447eccfdbe9, 0x8904b176dc7fdca6
    .dword 0xa71ce86f015a396e, 0x5cf6eb0655be71e5
    .dword 0x74175c68c3ef6512, 0xe53e3b866f0d0b35
    .dword 0x23f5683856ab9467, 0x25f6118a9512d3dd
    .dword 0x1e69144f575ab0c4, 0xc6471f337476f162
    .dword 0xb7c36bc55e96f0e5, 0x293d8b763db701e8
    .dword 0xb4790ca67850f9b8, 0x947b3f5edf8dc9d6
    .dword 0x98f357d005848157, 0xd76300c1748f45a3
    .dword 0x2fb48c39041a4185, 0x1553079c5658b33d
    .dword 0x459c3efe568c18b1, 0x46baf0bbfb0fc733
    .dword 0x6f74bb62d2c98651, 0x90cca565f045c2a0
    .dword 0xf585ba38f6bd41cf, 0x8fccda38fea3a611
    .dword 0xaff8821d285decc0, 0xfc27126b74442a03
    .dword 0x279fec4c121ebea8, 0x1e858829db040ece
    .dword 0x915e972d30a7365f, 0xc406bde54f651939
    .dword 0xe6f2b82bfd30f0f9, 0xaa1f2c954465b6b
    .dword 0x891cf6672e810407, 0x856bbe4bd7401e20
    .dword 0x76cf69adec222e1f, 0xd413beb4a97af37c
    .dword 0xa8825d1c4e8b2ba9, 0x7056f5582760a59d
    .dword 0xe49ce024a0c94124, 0xdf069421eb662f26
    .dword 0x4a94705c64d22bea, 0x5b346de0f6e1ee1c
    .dword 0x653d29737265873, 0x342d5c37149c50f9
    .dword 0x5b5684344b1ffeeb, 0x3385a65b8a1cc927
    .dword 0xbdfd2817dc15b13f, 0x27de6a55be0caa08
    .dword 0x6a0ccf6b684c443a, 0xd2990081ce34ea76
    .dword 0x843c3c6cb31327cf, 0xc21cc5769305870f
    .dword 0xacc4e6fef0d25991, 0x35afd49ecac75f8
    .dword 0x827057c3fbbc4c02, 0xf8db70d0526e6470
    .dword 0x73b319d4e7710969, 0x6e61ed5217430d35
    .dword 0x1112b8304df68973, 0x7d3dd39d5c5060e

    .align 12
data6:
    .dword 0x9b351f0f14f17d39, 0x88f9d80374944d17
    .dword 0xb8e39d8fca570940, 0xb48d5e235bd8fe9
    .dword 0xb9b307f0d6661385, 0x860fee068b6cd3a3
    .dword 0x31bdc6ee8add388, 0xe6c828e3fce3254f
    .dword 0x162985e7e907505e, 0xebd4466968dae4ed
    .dword 0x52cd036dc8afebff, 0xd21f6b4cff62d590
    .dword 0x4c3e2081c5aa5c2b, 0xcf012ce58610266e
    .dword 0x7331667504ded39a, 0x2b95028179f1692e
    .dword 0xc56e8de60ddaeac0, 0x2863cd927502c65
    .dword 0x559a5163ac0aaf61, 0xd031a49d7b008eb1
    .dword 0x302bf1a7cf1a4eee, 0xed85d3813a6b726a
    .dword 0x13556638e0488685, 0x5a2923db8b7ce2d4
    .dword 0x78417c0f666bd429, 0xc529c2cd897a96cb
    .dword 0x44b1205539c437fb, 0xf458749743049cf8
    .dword 0x6c68ed0f2d706c9c, 0xac169f833a8717d3
    .dword 0x97d434da293bfaef, 0x76e75795f4f4b15d
    .dword 0x736737c1ef328ca1, 0xadb7cb8900d8f3c0
    .dword 0x59a14f4857166930, 0x3e6513c063c2dd6b
    .dword 0x276318d8d6d2b776, 0xf473a84475e90c83
    .dword 0x426b4deef9cdd782, 0x6cc0bf92ab56f132
    .dword 0x18cc61baa9046ae2, 0x6ba7db117a2931fe
    .dword 0x4a196ee940147ab2, 0xfbe61dec1e23306b
    .dword 0xa4895b63757f7fcd, 0x9abea290b0721489
    .dword 0x9f6bad43aaf104f, 0x3b401f700ff3287b
    .dword 0xf8d48c790527ef5a, 0xa74c8d4424ff884f
    .dword 0x8c7504a09faa6be, 0x9837056a4ad17e95
    .dword 0xc25a64523d3ff1e6, 0x8d44d09babce1a9d
    .dword 0x8093f23a4d8d0311, 0x3819ee985a19478e
    .dword 0x73edb88f459f8711, 0xeb57f5068e9ee401
    .dword 0xf1c39771da85a2ba, 0x5862ab57b0292351
    .dword 0x438311ca63efcc5a, 0x9f54f0babe4e78b6
    .dword 0xae9c69aff088fc2, 0xdd116d3785a79c94
    .dword 0xcb14bbaa33a6a2de, 0xdc94522445e6be27
    .dword 0xbc104454204c102, 0x67f8583f67137fd7
    .dword 0x350f7d5a923b7023, 0xd1a4255fca429c1b
    .dword 0x36e5c044824a68e1, 0x146ea75711d601fa
    .dword 0x15902cc16d03e146, 0x80aa1476c1beb4be
    .dword 0x7ebd1ea33d993630, 0x8785845e49056350
    .dword 0x6d5c27e0d2f1bf94, 0x6b43ea5fdb5ab9f0
    .dword 0x62af99d9ab182e87, 0x2d7e22c05a450
    .dword 0xff4721eb7da94bfa, 0x4b373f6dd5fc8251
    .dword 0xa8b3a19904ba49ce, 0x271c3584b3d5dcb4
    .dword 0x784e3f256d06c07b, 0x8ba58222608c5e0c
    .dword 0xaf40e0472591b6d8, 0x8e8a340fbba44b43
    .dword 0xd1b3b23ae51b3a7b, 0x4ec94d56913493b
    .dword 0x1c7c205b600b3c33, 0xb5ce396b619b9e62
    .dword 0x590544861e24a19b, 0x8452a3c69e8e48d3
    .dword 0x7ad93518c6ad6ae, 0xf5e91467349d6329
    .dword 0x3b2820c04cca8305, 0xaf47b93dceb9a3a0
    .dword 0xe0f7577cfc1fcc27, 0x84a82b159bd6e943
    .dword 0x7fe3e2c8a158e905, 0x403b124cea70e140
    .dword 0xecf14c3374fd88ba, 0xf281d72d7c2a3624
    .dword 0xa0361832ebd56591, 0x59d9b8bf073fc9f2
    .dword 0x96ed89595bb647d, 0xae992327a9816551
    .dword 0x4eaab0507658dfed, 0x6e5b1b8e21bcffa6
    .dword 0xe88656d94f07bd61, 0xcfab68fae1cb8904
    .dword 0x8cfd3540c8be9f7b, 0x8fcaea5e06ddb6d3
    .dword 0x7d0bb2515aae45c0, 0x942b886dae5b9c4a
    .dword 0xaf0178bb98d596f8, 0xc69ea0a057d54be1
    .dword 0x34a84f48bd4a547a, 0x5bd45252496765de
    .dword 0x89c9ee24c21071b8, 0xef73115228a000e
    .dword 0x3d05c608d520fd4, 0xe14d0bd0b2936543
    .dword 0x8b11a7fc1ed9ccf1, 0x2f388dbff2719d4e
    .dword 0xcf76bc82f2c8724e, 0x43db5e8df4425af6

    .align 12
data7:
    .dword 0xff8dd374e4f09a5f, 0x8ff2f8a04952546c
    .dword 0xc1ee4efe3ee22a44, 0xbdc9106d2a805fd6
    .dword 0x1e3de8791645dc98, 0x47b27e26ec55a7ee
    .dword 0x6fbbf0d67c30deaa, 0xf168012733225735
    .dword 0xd446302d70f8f058, 0xab85cb9828f94a18
    .dword 0x9496e85629f3a465, 0xcbc727c48a4b251e
    .dword 0x6623ed4df7b63694, 0x26e987450b34028b
    .dword 0x667462f501659f54, 0xfd6fad79f3407ca8
    .dword 0xc7d7271eb5790b51, 0x4099ccf0a57c7e9e
    .dword 0xaadc65484fd92029, 0xab64a35f5a9fe231
    .dword 0x140011d13b186b11, 0x6a2eadbca4e4719f
    .dword 0xd254dbfe7d814eab, 0x676ff70962fd38c
    .dword 0xc3a08885cea667ca, 0xbc4dc59fa940bbd1
    .dword 0x312b5aeb271633b4, 0x62bfe4a02f0e8c5a
    .dword 0x3b88e6aa42bc6fd0, 0x289eab612aa2c22e
    .dword 0x9afc9535a5a92375, 0xe756606a2b74acfe
    .dword 0x5d905fb861bd57f0, 0x816f738a191dd267
    .dword 0x15fb75b5e43bbfca, 0x3568b2cbd9d4473e
    .dword 0xc758e7c93b255127, 0xc5ad71644d2a6046
    .dword 0x47ca39972d2997ca, 0xb5619b8dc33a6184
    .dword 0x95b72f27a02c8628, 0xa77c312fea9349ab
    .dword 0x1c0dedc41c0d54ed, 0xbd936deb989862a6
    .dword 0x5c61787fecd631c8, 0xea25dc8464d0dab9
    .dword 0xf22ee0adce0ba3d0, 0xb48344d26b1948aa
    .dword 0x6c722d41e408ab52, 0x7f46589faeedd732
    .dword 0x98a06f29e292052c, 0xbb7a1c9732c4d4ba
    .dword 0x3188fb399f17254d, 0x2569f42f939a38de
    .dword 0xc70f36a62bba9f98, 0x6ebbd54a7a3c5c1e
    .dword 0x741053c1f55c9861, 0x34c19d903546f206
    .dword 0xe8100724c47cd4c7, 0xcabd40b775950f49
    .dword 0x67fc6d68f5eb4f3c, 0x3a71d7ef7af6579e
    .dword 0xd61e1c045550fbb0, 0x540e8d211d4f1440
    .dword 0xfd03e1c8d8d26111, 0x955943d679fa8581
    .dword 0xf09e18c0c23108ad, 0x53c75b500ab93367
    .dword 0xa9aa30e1c9e0de6c, 0x9b6606421acbde3a
    .dword 0x747a80e6b85aacae, 0xdeb9dcd4ebb12bc
    .dword 0x71154f5d569962b6, 0x98ef2c175ccddfa8
    .dword 0x79ed386448cab8be, 0x5e6230dc9aa4f8f7
    .dword 0xcd02189667092f4b, 0xce3c309db300f5ce
    .dword 0x40b04703bc256cad, 0x553e82a4b27d4d69
    .dword 0xee4665d295e1ad66, 0x545b6734e035c023
    .dword 0x5951bddb9d298781, 0x7682b347b8e86ca3
    .dword 0x9c547a9bd95eb37e, 0x53d3e62925ad1aa1
    .dword 0x41e0144f3f4f9616, 0xa78e16815e5742a6
    .dword 0xa53c7970215b12ad, 0xa36a65913c16003
    .dword 0xce5a9b5b142ead2c, 0xf2d0382d8e8f71a5
    .dword 0x714dd4c91c5a4422, 0x45c9e2485b86eec4
    .dword 0xfe8ce56d7a2fc2cc, 0xdba8bd530c31b1c3
    .dword 0x9d3a9d7baf3b7ea6, 0xf08ce264ea1c3e16
    .dword 0xbb408f9eadecb86c, 0x3d404e8269952555
    .dword 0x7049b15528e6b1c6, 0x336cd5b7291db33a
    .dword 0xf376b12b5a5ac456, 0x97aea6a09af31bc9
    .dword 0xc113d67caadd1a4c, 0xce911677c1912f88
    .dword 0x85b740b9b8167a3a, 0xbcb54340d743e295
    .dword 0x72627b641d5ead02, 0x10de2e8603a7b1dc
    .dword 0x1b5f63444cdca264, 0xe3f622ea71ce386a
    .dword 0x90d43a5f01219954, 0x1d31044c5428791e
    .dword 0x7635bb6e5124dd86, 0x46affd94e1c14c5c
    .dword 0x462f271aa2249d73, 0x1d1fd908fbaf0f44
    .dword 0x8d62e83417185f1e, 0x7942cda9170c865
    .dword 0xa5d20a8948f3d342, 0xd6ea4e18aa20c250
    .dword 0x9d36785a101777cf, 0x2471317e55aa1cad
    .dword 0x685dde75876b3d67, 0x7ba242edce667a37
    .dword 0xbefc906ee3c464, 0x7794f70d099f473a


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
