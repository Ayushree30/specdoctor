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
pfx.bb0.l0:         andi x22, x22, 0x3f8                      
                    la x19, data2                             
                    add x22, x22, x19                         
                    fld f0, 24(x22)                           
pfx.bb0.l1:         andi x21, x21, 0x3f8                      
                    la x20, data0                             
                    add x21, x21, x20                         
                    fld f1, 24(x21)                           
pfx.bb0.l2:         andi x20, x20, 0x3f8                      
                    la x22, data7                             
                    add x20, x20, x22                         
                    fld f2, 16(x20)                           
pfx.bb0.l3:         andi x18, x18, 0x3f8                      
                    la x19, data6                             
                    add x18, x18, x19                         
                    fld f3, 0(x18)                            
pfx.bb0.l4:         andi x21, x21, 0x3f8                      
                    la x19, data2                             
                    add x21, x21, x19                         
                    fld f4, 24(x21)                           
pfx.bb0.l5:         andi x21, x21, 0x3f8                      
                    la x20, data4                             
                    add x21, x21, x20                         
                    fld f5, 24(x21)                           
pfx.bb0.l6:         andi x22, x22, 0x3f8                      
                    la x20, data0                             
                    add x22, x22, x20                         
                    fld f6, 16(x22)                           
pfx.bb0.l7:         andi x19, x19, 0x3f8                      
                    la x18, data4                             
                    add x19, x19, x18                         
                    fld f7, 8(x19)                            
pfx.bb0.l8:         andi x20, x20, 0x3f8                      
                    la x18, data6                             
                    add x20, x20, x18                         
                    fld f8, 0(x20)                            
pfx.bb0.l9:         andi x18, x18, 0x3f8                      
                    la x20, data0                             
                    add x18, x18, x20                         
                    fld f9, 8(x18)                            
pfx.bb0.l10:        addi x18, zero, 1887                      
pfx.bb0.l11:        addi x19, zero, 1771                      
pfx.bb0.l12:        addi x20, zero, 648                       
pfx.bb0.l13:        addi x21, zero, 674                       
pfx.bb0.l14:        addi x22, zero, 938                       
pfx.bb0.l15:        addi x23, zero, 543                       
pfx.bb0.l16:        addi x24, zero, 561                       
pfx.bb0.l17:        addi x25, zero, 469                       
pfx.bb0.l18:        addi x26, zero, 1023                      
pfx.bb0.l19:        addi x27, zero, 1530                      
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
prp0.entry.l0:      fmv.w.x f2, x18                           
prp0.entry.l1:      flt.d x18, f2, f1                         
prp0.entry.l2:      mulhsu x18, x22, x19                      
prp0.entry.l3:      call fn3                                  
prp0.entry.l4:      fdiv.d f3, f1, f2, rdn                    
prp0.entry.l5:      fsgnj.d f0, f2, f1                        
prp0.entry.l6:      call fn4                                  
prp0.entry.l7:      call fn0                                  
prp0.entry.l8:      bgeu x19, x18, prp0.bb2                   
prp0.bb0:
prp0.bb0.l0:        fcvt.lu.s x21, f4                         
prp0.bb0.l1:        fclass.d x22, f3                          
prp0.bb0.l2:        fdiv.s f0, f3, f4, rne                    
prp0.bb0.l3:        fcvt.lu.d x22, f2                         
prp0.bb0.l4:        fsub.d f1, f2, f4, dyn                    
prp0.bb0.l5:        fcvt.d.l f3, x22                          
prp0.bb0.l6:        fcvt.s.lu f4, x22                         
prp0.bb0.l7:        addiw x18, x21, 555                       
prp0.bb0.l8:        fmv.x.w x21, f2                           
prp0.bb0.l9:        fmadd.d f1, f3, f0, f2, rdn               
prp0.bb0.l10:       jal x18, prp0.exit                        
prp0.bb1:
prp0.bb1.l0:        sraiw x21, x19, 9                         
prp0.bb1.l1:        beq x18, x21, prp0.exit                   
prp0.bb1.l2:        slliw x18, x19, 30                        
prp0.bb1.l3:        fcvt.d.s f2, f2                           
prp0.bb1.l4:        addi x20, x21, 1391                       
prp0.bb1.l5:        lui x18, 376                              
prp0.bb1.l6:        fsgnj.d f1, f4, f3                        
prp0.bb1.l7:        la x19, prp0.bb2                          
                    jalr x21, 0(x19)                          
prp0.bb2:
prp0.bb2.l0:        srai x22, x21, 41                         
prp0.bb2.l1:        slliw x20, x21, 18                        
prp0.bb2.l2:        fsgnjn.d f2, f1, f3                       
prp0.bb2.l3:        fcvt.lu.s x19, f0                         
prp0.bb2.l4:        call fn2                                  
prp0.bb2.l5:        fcvt.s.w f0, x19                          
prp0.bb2.l6:        sub x18, x21, x20                         
prp0.bb2.l7:        fmax.s f4, f0, f2                         
prp0.bb2.l8:        bne x20, x21, prp0.exit                   
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      fcvt.d.lu f1, x19                         
prp1.entry.l1:      mulw x19, x21, x20                        
prp1.entry.l2:      divu x21, x19, x18                        
prp1.entry.l3:      call fn3                                  
prp1.entry.l4:      fle.s x18, f2, f0                         
prp1.entry.l5:      beq x19, x18, prp1.bb2                    
prp1.bb0:
prp1.bb0.l0:        auipc x20, 656                            
prp1.bb0.l1:        fcvt.lu.d x22, f1                         
prp1.bb0.l2:        fsgnjn.d f1, f0, f3                       
prp1.bb0.l3:        srai x20, x22, 28                         
prp1.bb0.l4:        remu x21, x20, x18                        
prp1.bb0.l5:        jal x21, prp1.bb1                         
prp1.bb1:
prp1.bb1.l0:        call fn1                                  
prp1.bb1.l1:        fcvt.d.l f4, x21                          
prp1.bb1.l2:        sltiu x19, x20, 1236                      
prp1.bb1.l3:        ori x18, x19, 1445                        
prp1.bb1.l4:        fcvt.s.d f3, f3                           
prp1.bb1.l5:        div x21, x19, x22                         
prp1.bb1.l6:        fmv.x.d x19, f0                           
prp1.bb1.l7:        jal x20, prp1.bb2                         
prp1.bb2:
prp1.bb2.l0:        fle.d x22, f1, f2                         
prp1.bb2.l1:        mulhu x19, x20, x18                       
prp1.bb2.l2:        fcvt.s.w f0, x21                          
prp1.bb2.l3:        fmv.x.d x20, f1                           
prp1.bb2.l4:        fcvt.l.s x22, f1                          
prp1.bb2.l5:        call fn1                                  
prp1.bb2.l6:        srl x20, x21, x19                         
prp1.bb2.l7:        bne x20, x19, prp1.bb3                    
prp1.bb3:
prp1.bb3.l0:        call fn0                                  
prp1.bb3.l1:        fcvt.w.s x22, f0                          
prp1.bb3.l2:        mulhsu x20, x19, x22                      
prp1.bb3.l3:        flt.d x19, f4, f1                         
prp1.bb3.l4:        fmsub.d f3, f2, f0, f1, rmm               
prp1.bb3.l5:        sltu x22, x19, x21                        
prp1.bb3.l6:        call fn1                                  
prp1.bb3.l7:        fnmsub.d f4, f1, f2, f0, rup              
prp1.bb3.l8:        bge x21, x19, prp1.exit                   
prp1.bb4:
prp1.bb4.l0:        slli x19, x18, 4                          
prp1.bb4.l1:        sraiw x20, x21, 6                         
prp1.bb4.l2:        fmv.x.d x22, f2                           
prp1.bb4.l3:        fcvt.d.wu f4, x19                         
prp1.bb4.l4:        slli x18, x21, 30                         
prp1.bb4.l5:        call fn2                                  
prp1.bb4.l6:        fcvt.l.s x19, f4                          
prp1.bb4.l7:        rem x19, x20, x22                         
prp1.bb4.l8:        feq.d x21, f1, f3                         
prp1.bb4.l9:        la x20, prp1.exit                         
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
tc.entry.l0:        call fn3                                  
tc.entry.l1:        fcvt.w.d x22, f3                          
tc.entry.l2:        slti x18, x21, 1202                       
tc.entry.l3:        fmax.d f2, f3, f0                         
tc.entry.l4:        fmv.x.d x19, f2                           
tc.entry.l5:        fmv.x.d x20, f2                           
tc.entry.l6:        fclass.d x20, f1                          
tc.entry.l7:        blt x21, x22, tc.bb0                      
tc.bb0:
tc.bb0.l0:          addiw x18, x22, 1109                      
tc.bb0.l1:          fmv.x.d x20, f1                           
tc.bb0.l2:          remuw x21, x20, x22                       
tc.bb0.l3:          fmadd.d f1, f2, f4, f3, rup               
tc.bb0.l4:          addi x20, x21, 938                        
tc.bb0.l5:          bge x20, x19, tc.bb2                      
tc.bb0.l6:          addiw x21, x20, 1122                      
tc.bb0.l7:          sraiw x19, x20, 30                        
tc.bb0.l8:          bltu x21, x22, tc.bb2                     
tc.bb1:
tc.bb1.l0:          xori x22, x19, 1537                       
tc.bb1.l1:          mulhu x21, x20, x19                       
tc.bb1.l2:          divw x21, x20, x22                        
tc.bb1.l3:          andi x21, x21, 0x3f8                      
                    la x20, data7                             
                    add x21, x21, x20                         
                    lbu x22, 8(x21)                           
tc.bb1.l4:          andi x21, x21, 0x3f8                      
                    la x18, data7                             
                    add x21, x21, x18                         
                    lhu x22, 2(x21)                           
tc.bb1.l5:          andi x19, x19, 0x3f8                      
                    la x20, data1                             
                    add x19, x19, x20                         
                    amoor.d x22, x21, (x19)                   
tc.bb1.l6:          andi x18, x18, 0x3f8                      
                    la x21, data4                             
                    add x18, x18, x21                         
                    lh x19, 8(x18)                            
tc.bb1.l7:          bgeu x18, x20, tc.exit                    
tc.bb2:
tc.bb2.l0:          fsub.d f3, f1, f2, rup                    
tc.bb2.l1:          fence                                     
tc.bb2.l2:          fsqrt.s f1, f0, rup                       
tc.bb2.l3:          fsgnj.d f1, f0, f3                        
tc.bb2.l4:          andi x20, x20, 0x3f8                      
                    la x19, data7                             
                    add x20, x20, x19                         
                    amoxor.w x22, x21, (x20)                  
tc.bb2.l5:          andi x19, x19, 0x3f8                      
                    la x22, data4                             
                    add x19, x19, x22                         
                    amomaxu.d x20, x18, (x19)                 
tc.bb2.l6:          fcvt.d.w f2, x22                          
tc.bb2.l7:          jal x22, tc.bb3                           
tc.bb3:
tc.bb3.l0:          fmin.d f2, f3, f0                         
tc.bb3.l1:          rem x22, x18, x20                         
tc.bb3.l2:          flt.s x18, f4, f3                         
tc.bb3.l3:          call fn4                                  
tc.bb3.l4:          fsub.s f3, f4, f1, rdn                    
tc.bb3.l5:          addi x21, x19, 1836                       
tc.bb3.l6:          sraiw x19, x21, 25                        
tc.bb3.l7:          remuw x21, x19, x20                       
tc.bb3.l8:          bge x20, x18, tc.exit                     
tc.bb3.l9:          bge x18, x21, tc.exit                     
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
fn0.entry.l0:       fcvt.w.s x24, f9                          
fn0.entry.l1:       addi x27, x26, 313                        
fn0.entry.l2:       fmv.x.d x23, f6                           
fn0.entry.l3:       fcvt.d.lu f6, x23                         
fn0.entry.l4:       fmin.d f7, f5, f6                         
fn0.entry.l5:       fmin.s f6, f8, f9                         
fn0.entry.l6:       rem x25, x23, x24                         
fn0.entry.l7:       mulhu x25, x24, x26                       
fn0.entry.l8:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       srl x27, x25, x24                         
fn1.entry.l1:       andi x25, x27, 1097                       
fn1.entry.l2:       mulh x27, x24, x25                        
fn1.entry.l3:       fclass.d x25, f7                          
fn1.entry.l4:       fcvt.s.wu f5, x24                         
fn1.entry.l5:       fmv.d.x f7, x23                           
fn1.entry.l6:       fsgnjx.d f9, f5, f7                       
fn1.entry.l7:       fmul.s f7, f9, f6, rup                    
fn1.entry.l8:       ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       fmadd.d f5, f6, f7, f9, dyn               
fn2.entry.l1:       fsub.d f9, f8, f7, rne                    
fn2.entry.l2:       fmv.x.w x27, f7                           
fn2.entry.l3:       fclass.d x24, f7                          
fn2.entry.l4:       fsub.s f6, f8, f9, rne                    
fn2.entry.l5:       addiw x25, x26, 1731                      
fn2.entry.l6:       and x23, x24, x26                         
fn2.entry.l7:       fsub.s f5, f8, f9, rmm                    
fn2.entry.l8:       fcvt.s.lu f9, x24                         
fn2.entry.l9:       addiw x23, x26, 79                        
fn2.entry.l10:      ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       remw x26, x25, x24                        
fn3.entry.l1:       fclass.d x25, f7                          
fn3.entry.l2:       divuw x25, x27, x24                       
fn3.entry.l3:       feq.s x26, f9, f5                         
fn3.entry.l4:       fcvt.d.l f5, x27                          
fn3.entry.l5:       fcvt.d.w f6, x25                          
fn3.entry.l6:       fclass.s x23, f5                          
fn3.entry.l7:       fsub.s f9, f8, f6, rne                    
fn3.entry.l8:       ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       fadd.d f6, f9, f7, rup                    
fn4.entry.l1:       fmsub.d f9, f7, f8, f5, rdn               
fn4.entry.l2:       fcvt.l.s x23, f8                          
fn4.entry.l3:       flt.d x27, f9, f8                         
fn4.entry.l4:       fcvt.l.d x24, f8                          
fn4.entry.l5:       mulw x23, x27, x25                        
fn4.entry.l6:       slliw x25, x27, 4                         
fn4.entry.l7:       mulh x23, x24, x26                        
fn4.entry.l8:       fcvt.l.d x26, f7                          
fn4.entry.l9:       ret                                       
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
    .dword 0x7465d2b4ba4bdb2f, 0xaab3d7bd651b4e76
    .dword 0xf705789f695ac895, 0x571a3e7b45715acb
    .dword 0xe4cefd8e81fc30c7, 0x43a66dafddb44225
    .dword 0xf402a7f2d62f3550, 0xb246672a91e1a751
    .dword 0xb3c61bfd17680466, 0x6523932d88af197b
    .dword 0x6f66c4ffe8d50550, 0x2556c67ed12a3927
    .dword 0xdce041098f91d2b2, 0x72224494650d0260
    .dword 0x4f0207eb744b15, 0xb09379b50011c494
    .dword 0x8d6e5003d157e4d0, 0xd4694b6601032019
    .dword 0xbfb27a79c1cfcd43, 0xcf3b33cbd0740fa7
    .dword 0xfbab97fa7cde62ae, 0x813f3e17c92f40b6
    .dword 0xeeffbe5c539b84cb, 0x33f48053571f21cb
    .dword 0xabd06bfdce81fc63, 0x1be8fa931a7715f2
    .dword 0x2e4b99f6e2de983e, 0x92d702e1b8f3975f
    .dword 0xacf3ef693ae92f20, 0xc22ff34e747d1b4f
    .dword 0x64ced656373c7209, 0x9627137e970c6650
    .dword 0xf1360a9b624d9b8f, 0x8932b0aa257d3eac
    .dword 0x701ed361593253d, 0x876e20f8a7992faf
    .dword 0xb6642b62a35b3586, 0xd029e49727a4417f
    .dword 0x5f9aaa568402b460, 0xbb70e759ebfe533e
    .dword 0x23d5b77d4b85807c, 0x952f605ef589a30f
    .dword 0x4a2d6b210dcf9cfe, 0xa3a8c51ecd6bb82b
    .dword 0x447f1d41964f3478, 0x33e373a058e1ea2b
    .dword 0x677dd175ab62b174, 0xa9b515de56f4a2f4
    .dword 0x32792a94c1140eaa, 0xf925d389400323b0
    .dword 0xe1dfb39f6252ad39, 0x3612ebccdbcfb74c
    .dword 0x9f47c877b207237e, 0xbe0cad1241b138dd
    .dword 0x5208d25097341608, 0x6fa8e5804ef9dceb
    .dword 0xf10eb1ca785d18e6, 0x251ca529ea84c567
    .dword 0xf0f64e9d08f23355, 0xb2f97b9b1a5b1381
    .dword 0x5722c16b85c8b890, 0xb8241178fb93a6c4
    .dword 0xde2856ea074700ff, 0xacf4f94c396b1c46
    .dword 0x2d9f5bbe1419558, 0x329a6de6b9cb6b8c
    .dword 0x10e7f30de6154fd0, 0x4d8390d211f562b2
    .dword 0x5514c3e2e17eb4be, 0xdacea1f7113d760c
    .dword 0x69c43e191d04eae0, 0x116e242385909c9f
    .dword 0x105e999377d06792, 0x61cc19eeb2801c8f
    .dword 0xdbf7c23c863ed6a4, 0x4c6bbd10c2278855
    .dword 0x5387ccd57284ec9c, 0x84bf1b97f0df5cce
    .dword 0xc0bc66c7ce2d4994, 0x2f3a460604500f43
    .dword 0x2281e2cf032e6056, 0xcc7894ac8320e3e1
    .dword 0xf97a2a048cc9714f, 0xcfccaeca87aab709
    .dword 0x9225fc518d88c398, 0x57944a718f2c3d34
    .dword 0x7cf8e9e77c063ad0, 0x387d4c4298b7c2fc
    .dword 0xe7a58f6d2687c857, 0x4e90d6a8c049e858
    .dword 0x50c2aac55c149bdd, 0x8236ac2a0c888e05
    .dword 0x432b683c839ef51e, 0x6d80fa6514184441
    .dword 0x8d981b4a880e4452, 0x12ddb09a777e68ab
    .dword 0x947d26828f81a402, 0xb2f034f44c91d491
    .dword 0x281c397648e445ad, 0x806c2eb5935c6f1a
    .dword 0x6b36a1f43dfbc720, 0xcdf67ad85cb45877
    .dword 0x94f22182383a9027, 0xb70bed12de0702f4
    .dword 0xbca024613482f2b6, 0x870f86e7d550f3b2
    .dword 0x6f79deb5178b44cd, 0x58983eee88c349be
    .dword 0x97d513a669747bab, 0xf3ceb43dd8248225
    .dword 0xa51e74e9c8b7e0ff, 0x2cdcff48f358a221
    .dword 0x47166265a8ce2596, 0xf897795dea9fce71
    .dword 0x90791148e75377ea, 0x185659510562657
    .dword 0x51b6c4525177e957, 0x9b69ac75d3ebe743
    .dword 0xc70b13777cc18229, 0x705f63c653208fb3
    .dword 0xe2ae052ec64b05c9, 0xe428707ec90026c2
    .dword 0xdea055eb5623ed69, 0x9178826b139f4a55
    .dword 0x79d30c04e2080ebb, 0x47759b060e083edc
    .dword 0x70d4a71b5977737a, 0x499d047dac2fad9b

    .align 12
data1:
    .dword 0xa405898a25ceb825, 0x7705201d489811be
    .dword 0x125518ba28b3aa80, 0xdbd699b7f7a2ded6
    .dword 0x913080d829374758, 0x5b622e175e482e0
    .dword 0x42a5f6c762e7b8c0, 0x235674dce692ba77
    .dword 0xbd80567a1e8541de, 0x2c9c09e1c1f792c4
    .dword 0x274d6c54192f41bc, 0x29077bc8a3f39340
    .dword 0xffa422e992c4a4d7, 0xe3659af325c75507
    .dword 0xe5ee7aa7c05ce65f, 0x777c93bd7d33d106
    .dword 0x6fa513be9ab9c091, 0x4d2b7546a1a203bd
    .dword 0x8147607c1a706870, 0xb69de624db0a15c7
    .dword 0xd112814206d0fecd, 0x5675cfae1d8aa178
    .dword 0xf43f9bf25f3efc40, 0xfcdcda781cc762f1
    .dword 0x51ed811869031fda, 0x40c92cfe8ca38e40
    .dword 0x321bbecb65d4b68f, 0xe7cd71c6c90c4c5a
    .dword 0x166e1e5ce8572a43, 0x2afdc7ddda07c904
    .dword 0x1655aeb10ce1b08e, 0x31e3fa87b11dd16b
    .dword 0xbac35c63221b017, 0x3a427653bc8bcd30
    .dword 0x2b4a0f9dbcbf5392, 0x984e5cac5b6cbccd
    .dword 0x66a2ae056a2a16f6, 0xd4eef785d6a03c68
    .dword 0x748b556dd168a4d3, 0xa0b11e0260e26dc0
    .dword 0x6110b565d4a9bda4, 0xfb8ebfd84483df52
    .dword 0x1f88d98d81bfb19f, 0x658c6b744d49547f
    .dword 0x6d52ec58e6dc4d3c, 0x5d2cadfb338d9bf6
    .dword 0xc0051db3fae5fa8d, 0x23e5b793e3815a88
    .dword 0x1de9c631898b42dc, 0xccea075c3f2bacbe
    .dword 0x83db220814ae4a15, 0xd3c02d2db1d8c542
    .dword 0x8cf88207d92b1014, 0xb5cc40b5a73738df
    .dword 0xfe7a7b64799d86c7, 0x9d2b96a32dc45a82
    .dword 0x85537eedb1e4ead7, 0x38df5179e93e4c61
    .dword 0xca10375d1aeb27b, 0xf8e82631e30f95a5
    .dword 0x38eb47cb218aa672, 0xc318bc819d0cf8e3
    .dword 0xa8515312fbf71745, 0xe4c0aa2ed25097c2
    .dword 0x8b46025a8255af3c, 0x79aaae40b88cc0c7
    .dword 0x1618412a021d6e12, 0x5bbf498baff91006
    .dword 0xaa33ddb9a9c9d925, 0x500e0e87c25506d3
    .dword 0x3571c71d8a8cb9fe, 0xb707a56ba812c035
    .dword 0xf99f2fde2005637a, 0x9c230cd998f3e247
    .dword 0xc61182d7fd94d04e, 0xf193f784f012da1
    .dword 0xe61282315a654014, 0x8f621b91a5d882ff
    .dword 0x50c99370d0ef3bf, 0x76772a0957164fa8
    .dword 0xe483d7fd9eca710d, 0xd2e9995e727ad87b
    .dword 0xfa71ad4aaec0ce64, 0xb391ed6881fac988
    .dword 0x38bcca3a725480b9, 0xa6fa8c62413299c9
    .dword 0x8a93f1f95ceae95a, 0x5f740140cc01ed7
    .dword 0x5243d45e93e7221f, 0xc13df3a3e3cc5c7
    .dword 0x1de75eda7fa7639f, 0x26468df4a2c48645
    .dword 0x7d49d2b1703935f1, 0x1b86806f8e761129
    .dword 0xa53f30c44352ebd9, 0x93e5cfaf15a65f16
    .dword 0x2026f0be69972f15, 0xa4abc35d571ff7dc
    .dword 0x2219ca754c7eecfe, 0xc077139f5b83893f
    .dword 0xe23d7dc220d30eec, 0x886a44c443f686d8
    .dword 0x75d81aaf28f8e3ae, 0xf4ae5df5be9aa2a3
    .dword 0xc383b9dae59ee713, 0x49dd35b46121f09e
    .dword 0x649c601f4d3e3271, 0x6fa2437ab6c99af6
    .dword 0xa6f3a6d1f301b6c, 0xda48c105196f555
    .dword 0x3ca3d13c6af8e81b, 0xdbb04e0c0e081a34
    .dword 0xff0a922ac1fb0ddd, 0x984a7e6ffa7ebd37
    .dword 0xe9af03aa8554fc76, 0xe26e62278825db9
    .dword 0x1d897d35e549711c, 0xbc7eb3a98f3e5c7c
    .dword 0x69384e3a3f6b1499, 0x3bbc3e9b860fc23e
    .dword 0xbdde00e17d1798d7, 0x465ae3666dbe3d96
    .dword 0xa0417672a58626c5, 0xd41e923ba7790c52
    .dword 0x8438f4c6b11f427f, 0xecb027e961cdec5e
    .dword 0xf1110fd83279e894, 0x4c15f2d594916e92

    .align 12
data2:
    .dword 0x727b1b99373aadc0, 0xa5a19566c146ccf0
    .dword 0x77247618d4a5bdf8, 0x13af16bcba60029d
    .dword 0x3332baffe7bc1eb8, 0x65120ec9af3d5726
    .dword 0xf4032aab96606f9a, 0x1d1f5d2356b9de41
    .dword 0xe4155fd1d37104af, 0x4b4de8125d18449b
    .dword 0x9498829d673205b5, 0x8b7e01bf08af33e6
    .dword 0x56749d956cde7dda, 0xe77eadea9431784f
    .dword 0x63377af892c77807, 0xb7318f4c2d53b970
    .dword 0x8b176e637d85f4ce, 0x2e88b09eb0104a46
    .dword 0xbfffb2afad149f68, 0x158abe8e85ca23c2
    .dword 0x9feecb4f8a8e75bb, 0x40464fc53f2cf1ea
    .dword 0x20d8541e2c45751e, 0x89a14c475c823d44
    .dword 0x67db52a2a414ccc5, 0x4737b1da1d2fd616
    .dword 0xd586719330a3839c, 0xbadec06f43c49248
    .dword 0x60f67fff638e0839, 0x8e032af0ad3d6ec6
    .dword 0xad4f590c5bdd5a15, 0xade31ef7eb5631be
    .dword 0x46ef7acb2c2506ca, 0x4e463cfaf93d94ed
    .dword 0x10fe3a28e9ae9835, 0xdcdbfc03974ace8a
    .dword 0xece9e727b7cc7ae9, 0x3fc6279d87f6b59b
    .dword 0xc620336d74c7a4f0, 0x1ec1823e57aca1c2
    .dword 0xa9cc8ba2358c268c, 0x892249913a346362
    .dword 0xeb58c09ddeb3defc, 0x3c19022083444563
    .dword 0xa3c0ffdc4fe9cdbb, 0xda36ea7a22297006
    .dword 0x466665bbf0b8b655, 0x6166fd6a7824fe36
    .dword 0xd8295161038868ce, 0x4a3b443112c23c8d
    .dword 0x5ee40bb21546b3e0, 0x9a045b0fe340efc0
    .dword 0xfea2fd341642347, 0xa247faa5baa2fd45
    .dword 0x9f0a5abb0535a1a9, 0x3dafa412108d949c
    .dword 0xc7abfe244cc27e28, 0xc717f2ef5709f384
    .dword 0xbe7dde41bc52e65a, 0xac15534424c98569
    .dword 0xee82995c890fc5a8, 0x69573a822b0dfa32
    .dword 0x99b850a040e717be, 0x4faf058127414c34
    .dword 0xaf19e5187d7d3891, 0x84cb484426ab1c25
    .dword 0x8ece422a25dabfad, 0xdd660bd0270db08f
    .dword 0x611009516d32229b, 0x933f6378a32dac9e
    .dword 0x6a8dfddb5ffae93c, 0xa7d51ee68db0b236
    .dword 0xf80401422006cfb, 0xee044456836c5ced
    .dword 0xb734c0e91a3a519b, 0x2ecbcb19b647f566
    .dword 0x486f9806fcaa525c, 0x5dc3a10e106d160b
    .dword 0x4542f4dff43eda3c, 0x58f01091f4ae49a6
    .dword 0xb8c5097227ed0e71, 0xa1837cca6d2cacae
    .dword 0xf513c0bc07354256, 0x61a7f28b952132d1
    .dword 0x4fa3c099a138594d, 0x933c0033fff4cc97
    .dword 0xe35739259a387a02, 0x3d315e5b938bd3f5
    .dword 0x4218bca2ef0549da, 0x99613f357da46705
    .dword 0x5bfd4969a6ff46b7, 0x5cdd6dc89336c9ba
    .dword 0xd5a1e5706fe63769, 0x6c901145cd51cbaa
    .dword 0x2b03a80148c2b850, 0x1174eece6c7973d
    .dword 0xab934484f8e5e3c0, 0x21e4587701d64221
    .dword 0xe9014604330926d5, 0xcec4c39ca48fca73
    .dword 0xa9477ff67263899, 0x260b39ae4a9a5b3f
    .dword 0xc55935a4140d5db7, 0xa005a75cd2155026
    .dword 0xd4471366fc6299bc, 0xefc1035c179d5cce
    .dword 0xb7162f344a7ee234, 0x6dfbfa93530c22e1
    .dword 0xc34b9e54e96cd9ac, 0x3da23405b1db0e34
    .dword 0x6eeea09edf6376e, 0x360e01543a025584
    .dword 0xfe2b8ef90c83bd, 0x3a67b2dd3a177abc
    .dword 0xfd8121c2005f3e96, 0x7e77ee7ce7081c1a
    .dword 0x6c1923f796135f36, 0x26e01820679e214e
    .dword 0x9030bb8aad3e3ccb, 0x7e646188aa911506
    .dword 0xaf8628211a667608, 0x1746a47e612a1bf4
    .dword 0xe83b327c79a91286, 0x36f0a49e43789b2f
    .dword 0x7dde74e8ea56224a, 0xdaf6d7732497e848
    .dword 0xca495d5a99b04368, 0x21bbffd98e4c00e0

    .align 12
data3:
    .dword 0x22cd32770b03bb3c, 0x66a6ce63f9fe7794
    .dword 0xaa480103d45c9e38, 0xaaef0f4526abcd8d
    .dword 0xc98b63947169b82c, 0x9a071fdb09bc0c72
    .dword 0x7fdc39d898b5be0, 0xd041e664f6eac771
    .dword 0x60856ca37769c556, 0x5fcf3bc3708b53ec
    .dword 0x6e7cca17cb2d2b5e, 0x2cb6f5b50adb9d84
    .dword 0x246efcf566b7518b, 0xd0fd3ef5c08afd07
    .dword 0x8fdda9a699b8ffc2, 0x6a77a4d3817bb870
    .dword 0x15cdb025e7b9e3a9, 0xf0564e6fd6f81520
    .dword 0xace0e5bd6435fe13, 0x82798a7c590610ab
    .dword 0x839b6cc5714b495a, 0x103752a55a5cf2eb
    .dword 0x7530b726b87a0f29, 0x7b95211aaa18804a
    .dword 0x16b5ea6a9f5d307, 0x9edd52ffcd43fc7d
    .dword 0xdce3cf9546781416, 0x6b604ece4fda353b
    .dword 0xcdf5d86ba121f9e5, 0xfe474602e6575ada
    .dword 0x9b70664fcbddc72a, 0x5c251442d4b99315
    .dword 0xe95d0547fa1d5444, 0x8619896131422164
    .dword 0x2ae776e230ccde89, 0x2e9c1e53c2be8c36
    .dword 0x57651077873b8730, 0xaf74907e246e06d7
    .dword 0xa8d3d9b0b14f72c3, 0xd8c5704697eddb40
    .dword 0xbc8924a922c20148, 0xa7e20ad2d847e830
    .dword 0x9b8417ed3a2438a8, 0xdb113b64fac8fe08
    .dword 0xf1edafa14f5ed53, 0xa4d2f9e0be4e091e
    .dword 0xf444c9e3fc63f49e, 0x5f2230d5f820fdb8
    .dword 0x576839520728e334, 0xe0086a2067b4f61d
    .dword 0x69271a00b4b20149, 0xf1fe19b30a5902b9
    .dword 0x6cbf6d9abe294897, 0x91940d303c27053d
    .dword 0xe32d49ef16d2d85b, 0x565c744a3e5b98a8
    .dword 0x57ee4a0013a441b7, 0x781398573b84939
    .dword 0x2f46e3d6c2acef9, 0x46f355051964da59
    .dword 0xd42e1ef4977a44b5, 0x3de3a9d7cc822787
    .dword 0xd92156f9bf76a009, 0x69e9d73091ea3394
    .dword 0xc7a5a5d2ea055b10, 0x6f31f7829544457d
    .dword 0x6da03ab980d9c4f3, 0x136cdd723f0598a3
    .dword 0x4783f5ea9991f6c6, 0x633de0c7d1582be1
    .dword 0xa5df1d2713a2a98e, 0xe19e90662442b929
    .dword 0xb5743abcaf249d2b, 0x9a9cfaf613ceccf8
    .dword 0x31fb8a512f31281, 0x814a1311afcfd0d3
    .dword 0x5841f163fe8f352d, 0xc99aa90ad359e8cc
    .dword 0x16a5e5b753ce053d, 0x21f7a97919b7522b
    .dword 0x99f7e22f53c1bd06, 0xa65f7f16e5c50763
    .dword 0x29cd9f0580c1ab34, 0x5f251782d06b1f6b
    .dword 0x856928da303bff50, 0x18f5fd4e7f52d74e
    .dword 0x79e5fd47e062526c, 0xa556583ad04ed48b
    .dword 0x15c79f5e83fe792e, 0x281ea559c305e1a5
    .dword 0xa04d2d93a7b4c62, 0xe9960bea2809eeab
    .dword 0xac921768b41141df, 0xf0408d1dc3ca16a9
    .dword 0x456bdd925842367a, 0x2143e12e09a9afe9
    .dword 0xf51cf4615eb9d060, 0x264276a68cad5286
    .dword 0x570ffea45cf0ce76, 0xdf61f0608bb59693
    .dword 0x24df4423ed3106de, 0xb2af99139925aacf
    .dword 0x31be511b21233971, 0x24a3c9e15e6b35af
    .dword 0x6db354319ecbd46d, 0x1bff318e72f127e0
    .dword 0x521e0604f3bd85ea, 0x2d4cfeb99b170726
    .dword 0xc64e1e648058c10e, 0xada0c061958e7db4
    .dword 0xa8f87fd08acb6d7d, 0xb37cc630cd32c94a
    .dword 0xfad4c02c26e25054, 0x8bcd1306e62e50dc
    .dword 0x98d484ac14ff3726, 0xd7835f1eefb05f94
    .dword 0x8327ef2859b20005, 0xecb57bd51e13cc2
    .dword 0x7e26e52a58c2f51e, 0xc12805c5e9f57058
    .dword 0xa93f16a9e40d2e61, 0x4a76c786eb426f1b
    .dword 0x7ff0a747c49010b5, 0x5d16b6c5b5912b11
    .dword 0x5ef05b4a659f4897, 0x28ce62dccadb9707
    .dword 0x297548af9a6fdf77, 0x2a222623ae6e7e

    .align 12
data4:
    .dword 0x256da18a25d43186, 0x5d990028e0fcd42
    .dword 0x8d6ae629652e3b5d, 0x12c56aefead997d8
    .dword 0x11c474392f7c5a50, 0xca51549b85431a52
    .dword 0x8c939d924a9bfacf, 0xedc41457031464b
    .dword 0xa1802a2d9b7ce246, 0x40e983708de65fba
    .dword 0x93d7bd176ad51eaf, 0x4585d95b5373719b
    .dword 0x23f3d1f9401808b8, 0xd92c4b7c995d8e62
    .dword 0xbcce1e8e77916c24, 0x542ca3d6fb038ebc
    .dword 0x345b394aacea8f84, 0xe6f21160ee09e5f8
    .dword 0x3f47107bf187bc0d, 0x81fa5282f6ef5797
    .dword 0x36162d7a4afd000f, 0x284f47a0e2803f7b
    .dword 0x2e258e9d4c4af84, 0x6a0622f4f875883e
    .dword 0x1e0e0b8168363978, 0xe48e822a09fe10c2
    .dword 0xbd575ae96985f3b6, 0x7ad037adcaa9dbe4
    .dword 0x94173d548c86249d, 0x5c120f0e0705c058
    .dword 0x9904cd9cdac2ca7d, 0x81d9212496405fe0
    .dword 0x5418f433f572b2ff, 0x906c3fa34a7a3c5b
    .dword 0xf8aec648bea294ba, 0x329a268a87ac5128
    .dword 0xb39a5b7a432f9a01, 0x494b2c5b4a98d7ea
    .dword 0x91edffa38f6b3ead, 0x6254fc6f05143928
    .dword 0xa4c930b8b1944f64, 0x734b47302dbdbe8a
    .dword 0x790fe74d375c3574, 0xb918404283219f33
    .dword 0x5c0b1ed5c31ff7ba, 0x7782491af6a52200
    .dword 0x7bee158780cc3d50, 0x3a084bd2a0180789
    .dword 0x99f0e0ae7494530, 0x2ed8d49af7793054
    .dword 0xdc7e2d36c0c1f5d3, 0x4296f221cc647f24
    .dword 0xba4572c0a9bbf5ea, 0x6b9af0b9b531002f
    .dword 0xa371e9b98ac9eb97, 0x6a8d39a3573872fd
    .dword 0x3e7e8852e40073a, 0x44a21c387a87f54a
    .dword 0xd89984ebf6280a39, 0xbab8fbb29dd01eeb
    .dword 0x6e8edbb8426a05b3, 0x71d2c1eddc101cb1
    .dword 0x91afda9436df5d0a, 0x248b3b217a06371c
    .dword 0xb1d7e1a0a0acdef5, 0x968edd7b303aaa5e
    .dword 0x3203c5ce6401713e, 0x508293de81e394aa
    .dword 0x60f3b278630ba64e, 0xedf5d54ebca5bc99
    .dword 0x2ac05ed3f7eedc9a, 0x67203700dbeb694b
    .dword 0x1da56a2a41821d35, 0xcb353312506de9f5
    .dword 0x600041a0e0e118f2, 0xf37b99d2e3142900
    .dword 0xc14d0e6e4cb152e1, 0xf25bf59cc3098ff1
    .dword 0x501cf528ac644ee8, 0xcea712d86bb2a0fd
    .dword 0xb7e2a350f8784df6, 0x2b25024ab2c85cfe
    .dword 0xd1ac10788c227b35, 0x38546054beec03e1
    .dword 0x6f504f27783ade9c, 0xb8aa15e83d3f590
    .dword 0x58499567ebb6f401, 0x51ff0c6ad4b063ec
    .dword 0x4c0fa35c175226b5, 0xe9fec4808ee484a8
    .dword 0x445225cb803e82a, 0x8180421510fa30f3
    .dword 0xd932fbfe1afedc96, 0xa16267ec9657198d
    .dword 0xec5094fcc8b1bb20, 0x7b06865cd2fbb4a0
    .dword 0x7f560f8a1f7dd612, 0xfdec872b9f4a4270
    .dword 0xaf1c1cbdc68c0936, 0x8185f76f705299e7
    .dword 0x72ae7c37725e02fb, 0xa91b9d4b8ddf435
    .dword 0x336842c6bf8c2067, 0xe8a12acb1e5ed0fe
    .dword 0xd43dd09d6b0b0f86, 0xf623dc7874ede1d6
    .dword 0x4453974430129ba6, 0x1274ae2a35363851
    .dword 0x2fad900d8efa6ab5, 0x18ef08b27cd64099
    .dword 0x4970cd25bc63abd2, 0xc4cc5090a079f638
    .dword 0x7214bd1914335414, 0x7b9b281444582752
    .dword 0xc0fa8a346214bf85, 0x4448e53c6d70b16a
    .dword 0x86f71071a5df7e9a, 0xe6ea397a823f6def
    .dword 0x1d6e8d5f83719c54, 0xaa7f3a392f7343ac
    .dword 0xbc1af65ca35134d0, 0x4c8917af7c4f686
    .dword 0xcd13bbe785d750db, 0xf1de46c071042207
    .dword 0x4e2596b01975f35d, 0xb4f2fe3c5e2614c4
    .dword 0x7711270313140856, 0xf97ff59fc027f1b2

    .align 12
data5:
    .dword 0x156eef4ed84965a4, 0x309adf8745771af
    .dword 0x91ce79c63ffd4bae, 0x28e08d2c802c0a36
    .dword 0xadb81741fc96c83c, 0xc6238deb3380489c
    .dword 0x38be5a8363278c3e, 0x8f17e3f9ac9d58ff
    .dword 0xba22a3b6d5488034, 0x49a22acfa0771021
    .dword 0xa32a887515167e3, 0xfc0431d0d0f5b00d
    .dword 0x1a13b26c7cca7d16, 0xcf2f747ec7453c96
    .dword 0x5012a2d3349ac10a, 0x4de5ee9b65708df7
    .dword 0xff3b5af0e9160357, 0x568ca6fac2bd1cc1
    .dword 0xb548dcbf4dd25a37, 0xa1e02778612ea298
    .dword 0x9f474718eb4a3577, 0x386b2a904e7e1b5f
    .dword 0x8526c39609fb53e6, 0x4c588712fa74e949
    .dword 0xf762c3e0f2be23a6, 0xb356ec1acd7b77b9
    .dword 0x7a6388a017cd5339, 0x7fdd83b6e46e5054
    .dword 0x43194a4c528d8c3d, 0x625e488107021504
    .dword 0x48858f967a629f7c, 0x596069d759037afc
    .dword 0x398ee63965d0ff94, 0x793f9495ff46b414
    .dword 0xd86e5073f6fad785, 0xdf2b8bcddd7e310
    .dword 0xed0653b1b0004276, 0x3d5ff68b043a02e8
    .dword 0x1f413465e22ad79e, 0x2d869116e79977bf
    .dword 0xbbb8c6e8582ac363, 0x8a4ff38cb2e14879
    .dword 0xc26442365d34be5a, 0xc40d31fa590a4b0
    .dword 0xe5f211d64fbff4a2, 0x835f62f2cf12dc79
    .dword 0xfe5ca37a55cd6a57, 0xfe487e88103412d5
    .dword 0x3db388b9147b51a9, 0x9e26c18890f8c78e
    .dword 0x710fee8d370a8844, 0xaf99a4376aed1b8
    .dword 0x3e5337672e114c7b, 0x76ac38fbc45c05e1
    .dword 0x2bf06acd97fe4740, 0xfcad863496932a53
    .dword 0x8bcd140e38487c93, 0x71756f3a6d8e0df6
    .dword 0xe79cb230167ea7ef, 0xd674c65d15874013
    .dword 0xbac2919472ed6acd, 0x705830aa2c9b91cb
    .dword 0x71b3dcd647a3ede1, 0xbc95ae92530416e5
    .dword 0xfb214cad6a0ad598, 0xa23340a72fa41d74
    .dword 0xc52776175b42f0e0, 0x685e316670e28e85
    .dword 0x3b11e747cc05224b, 0x15a34d460fa555a9
    .dword 0x75dfc37c1e617896, 0x81fa4410b0be026f
    .dword 0x5b3ab8ee102b5f37, 0x25088df0b5ff117e
    .dword 0xee265473321e776b, 0x90149e9682c2ac00
    .dword 0x5dc9c3021859b80, 0xeb642a365c84d113
    .dword 0x688c686b121fc43a, 0x8d52e88edee23603
    .dword 0x34231f5479935839, 0x506cee79dc0875f6
    .dword 0x52f6f9809a63961b, 0x29ceca8dc9284f04
    .dword 0x930248525ae6645a, 0x8f26bdc14f3012d1
    .dword 0x84a8479f7de6f331, 0x72cfff1beb88d7e5
    .dword 0xa049617ca459d3d, 0x89c46f93f9c11212
    .dword 0xd9cdb9a16a73d57c, 0x137e6d6c0cc2c19e
    .dword 0xe51585e1cee308d3, 0xcd53b34de06abc99
    .dword 0x3a7ae3e14499284f, 0x92edbda4f6e1cd7b
    .dword 0x7b46fd2ecdec3b54, 0xf3209134533f8755
    .dword 0xaa1187a25f40b856, 0x35f0e1c277be24ee
    .dword 0xf790bacd156546a5, 0x3440a76f79561337
    .dword 0xbe004b649150c6bc, 0x8873656c39f1f31d
    .dword 0xa8ed000bdeac847a, 0xec0753228969b9b7
    .dword 0x7c0b84fd973c1d35, 0xcf8ea2d6c4b8e6d4
    .dword 0x66e738ee2aa5ad27, 0xdf8343e71dc8f202
    .dword 0x6d556c4a9f59dade, 0x4b10e9a05e62680e
    .dword 0x13697796083fea8d, 0xf91b7388f3df8fb
    .dword 0x9362c0cb3ac38893, 0xa50ea5a261916645
    .dword 0x95878297a729d320, 0xfa565edb88ef7ecc
    .dword 0x269a2028b55cb6c9, 0xb975d326489dac15
    .dword 0x8ac899357e2d3900, 0xd644858ee717311e
    .dword 0xa2a5bb2baade2905, 0x628fb5dfe002663b
    .dword 0x9c06c08d32818ba7, 0xe5ad019a829e2a7a
    .dword 0xbe65015f78c320ce, 0x53d210ede22813b6

    .align 12
data6:
    .dword 0x7a68f28f477c6a39, 0xa242eb62bef03ace
    .dword 0xe86e33bfe9e4ef82, 0x79bb35b6c5364996
    .dword 0x45a6b99027d70f1a, 0x622e69bdb17b0d7c
    .dword 0x524100171b8b2010, 0x92b878f04fb43dfc
    .dword 0xd8e19e73bd652723, 0x69776c6b60ba162b
    .dword 0x9cd18cd8f9e3cd27, 0xc52a89eca5f4b530
    .dword 0x82971b54ce74ba0a, 0x9624b88558b5823c
    .dword 0x60c45a63e548e8f1, 0x49fe090b3d11a99b
    .dword 0xc0ad5bf0eeb4bcb3, 0xd63e749110dd8ecd
    .dword 0x6fbc7aaf75e834bc, 0x6e031df504519163
    .dword 0x2fd81970f1a9dcf2, 0xe8704334b390a65d
    .dword 0xf22c4076473d1d7, 0xa510ad0389169243
    .dword 0xfe58212a75727d58, 0xee3e59b86d848bc4
    .dword 0xd1ba7b08d0b7f8c7, 0xae54a633c92a38a2
    .dword 0x4f551643041dbab1, 0xe03292f5535eae8f
    .dword 0x21cc8075e83448fe, 0xb29ae3fc1d63bf36
    .dword 0xfce1da947e7671d6, 0x7f5f9f821fe10530
    .dword 0xc1e43c03885f622, 0xe7186d728c64f362
    .dword 0x8273c406c39e3a33, 0x30e0a83ca451c329
    .dword 0x522566ada6cce8c8, 0x27323119ab62b73b
    .dword 0xdec799a4c680e4c0, 0xc11c498724e2ee8b
    .dword 0x2d095f653a313cc0, 0x60fe80f60476b97
    .dword 0x8fbf0cd227e8cdc7, 0xb676235dce0fd12b
    .dword 0x555b6a897b65d914, 0xdb77d74574253989
    .dword 0x1bea2ab089a63284, 0xeea5d769b2cb604f
    .dword 0x8df2d5f2fcd8bf57, 0xdbaa992aa9cc1576
    .dword 0x57c9ef148b90506, 0x3ade79f3d984fa95
    .dword 0x3ff2164f41bafadf, 0x157abf7db0b7b8dd
    .dword 0xdb89079efb055349, 0xb023615bee1d60b5
    .dword 0x513093647820e366, 0xce6fa575ffe0ce32
    .dword 0x90e1012f9062c6a7, 0xe26630452801f822
    .dword 0x385519921de96b45, 0x3e54cc8a6544b556
    .dword 0x6c225b07c07477f6, 0x7abd5ab17d89420d
    .dword 0x6452557d6c7bed2c, 0x276b205cbf72da38
    .dword 0x534e608dae4b2d0c, 0x6a917cbb317a6fe8
    .dword 0x7f62b7e9937bf63e, 0x1dec2544fb6f0c76
    .dword 0x596eab2c95e3ae2b, 0x3c981f9c07ef741d
    .dword 0xbb3e675933d71d99, 0x650e36337c7f86b5
    .dword 0x963d64477d9ca43e, 0xc104fb10fcde5d94
    .dword 0x70730a152f4318ad, 0xdb2a18d53babc4e5
    .dword 0x7ba6d5e8f43ef35e, 0xf4dd150741fb07ca
    .dword 0xc37caed80f2a22fb, 0x137b9fa56bdfe8e5
    .dword 0x5e9d1b3d0484e7cf, 0x86f3c78c49b1862f
    .dword 0xeec44e8dcdfebbfe, 0x98e28fc49035e770
    .dword 0x6b9841a5e2710db8, 0x2acdc1fb1d0e1b70
    .dword 0x18bc00eab98d11f2, 0xe5f11edaf806a9d9
    .dword 0xa5eab76ff2a242b5, 0x504a786a73be61a6
    .dword 0x7993c27eb1a1efe2, 0x151e04417e8c669d
    .dword 0xbcec2236580b0ca5, 0x946124d4a7fc9a50
    .dword 0xbb9699b15b045c6a, 0x94e9b3705879339
    .dword 0xa6fff5133661a7fe, 0x7556a83a94faa381
    .dword 0x3d7c852192529b9c, 0x36f8dd84eb9decef
    .dword 0xa1ae2e74f9c271ba, 0x5f2467d488a39551
    .dword 0xf5020d80ea60852a, 0x765f5fd7165d7651
    .dword 0x1f539bcdcf24f213, 0x1cb2998820b85c9c
    .dword 0x873315930dc0d437, 0xa7d1f1c0b4182951
    .dword 0x4d6aa73cd40d461e, 0x136ddf698ab324d2
    .dword 0x45187d681673da80, 0x592e91085f7d2a1f
    .dword 0x3155f0b87d70056b, 0x41413c70190b99ef
    .dword 0xb1b9c9de393a8ed, 0xb8f0003c8c2d3195
    .dword 0x388d758094e4656a, 0xf2fb5a9375ee3349
    .dword 0xa829a2d4673c34ed, 0x47d22951b3752931
    .dword 0x6c25f0c26ebd5382, 0xe3280f861af7326e
    .dword 0xf77b0c2fd582bba6, 0xde96c2f516d2de68

    .align 12
data7:
    .dword 0x7f6533d06e708e57, 0xc68245330b3bc4e9
    .dword 0x7885863ca5099faf, 0x4e060261aee05b59
    .dword 0xec5fc40be33bbc88, 0x50037d9e9ca0a88d
    .dword 0x4af877754a647824, 0xccad8ae656c5b63f
    .dword 0xf80e1f8227db70bf, 0x453ad970f81f121
    .dword 0xd7d34bfaadecc691, 0xc1f3d18eba1d8c4d
    .dword 0xa55faa9a68651cee, 0x12b6cbc132b5975f
    .dword 0x1d0fcb75e7030b61, 0xcc63a1c5b16319c8
    .dword 0xe2db6345671c1593, 0x2bf2187ecdd66a3
    .dword 0xa2dba8cb32e9b83f, 0xc0a9b7897790bde4
    .dword 0x40d8bdbeb89dae98, 0x683b67eee93e3518
    .dword 0xf3ceb9cedfc42813, 0xd8e9ca5595d6a006
    .dword 0x788db9eba3730367, 0x4e9ed75323137439
    .dword 0x11d991c9817b6b7e, 0xb08587287d3b817b
    .dword 0x8a9ec247c1ebcf0f, 0xd3b21cd610ca8e35
    .dword 0x418a1b9c3b3486d8, 0x98b0dee739430402
    .dword 0x7b886dab4413aff5, 0x9846bb3ee70aa086
    .dword 0x1afcb73b10d8b2d6, 0xb66eb690c7ec3fd8
    .dword 0x6d76d4983dd1e2f3, 0x7d58f18b9709ea4c
    .dword 0xee4a285c50c37779, 0xc1ca92ef503888c7
    .dword 0xd5964349911a3571, 0x79bfb4b01673cbbc
    .dword 0x82ed2a002165efe3, 0x5b4958765cc59d6
    .dword 0xb446da83eeeb88d0, 0x25d91db88f56c434
    .dword 0xb45a6826d963c01c, 0xc52d4c46dea5b818
    .dword 0xe29dbf961052ad18, 0x8910c1feaeb6d3ef
    .dword 0x789c114e6b3a70af, 0x5710f72eae1a6e45
    .dword 0xeac571abe021452b, 0xd61b63d72d365432
    .dword 0x2968211fb3d54def, 0x5cd41263b8c6a2bd
    .dword 0x9f534c1abaadae01, 0x4cc8a8c145c2b2f7
    .dword 0x8dda4294faa341f2, 0x906b0d328c47e3fb
    .dword 0xddb4091465fc34b, 0xcc9ee1a4a40d1f7b
    .dword 0xa8c24ce8d91a90a9, 0xf62666444edea2f2
    .dword 0xc9fe66ae4585dbe2, 0x6d197410be6f2162
    .dword 0xee450e9d1324c476, 0xba5f04451c46e196
    .dword 0x7042276c7d3f75c8, 0xdaa20df87f2816f9
    .dword 0xda665070fd0c90a3, 0xe3f20b7d578da1a7
    .dword 0xb4e7352996062692, 0x2d6ca7a69b1fd4f4
    .dword 0x3ba33a6cfa26effe, 0xb9baacaf79c3f7d2
    .dword 0xfd4505d8d14c3a96, 0xbe70cca1f098b4ea
    .dword 0xddf9d348e128d422, 0x7df8bd61401220d9
    .dword 0x2f209bb1325295e4, 0x3fea3bdcad72196
    .dword 0xee705e41d3cbcdde, 0xb74c8e2e9bcdea79
    .dword 0x419eba7eba37150, 0xd0d172f17d7674b8
    .dword 0xc05858f1a3ba8448, 0xecc0a62bfd434cf7
    .dword 0x470f8e3eb5a38e92, 0xe96dcfe495d9c154
    .dword 0xae80023e034ac01f, 0x26ec33a39461c751
    .dword 0x21a336f74df8de9e, 0x7b5832568909c309
    .dword 0x767d19b94941ec96, 0x3b5576601604cef3
    .dword 0xf5f139c7b194eb0b, 0x1c7d4dec05b61eae
    .dword 0xb2e9ce2437422138, 0xb27cd889f39b55b2
    .dword 0x8c392fb6864d298f, 0x2ad6fcc5dc3408d3
    .dword 0x10c7233e8c88720f, 0xb0246d66359cd7c7
    .dword 0x80b10c4108a874c8, 0xe030b11910508414
    .dword 0x97628330844c3691, 0x41f67c37c7534b90
    .dword 0x4254bb60ea5dd3ad, 0xb9ef5766479a5486
    .dword 0xa4f224a495cc0ffe, 0xcd42036c7bcd4e7f
    .dword 0x4b9101e45b52304d, 0xf85ceeb20c6a610c
    .dword 0x69692135b0fc3a4c, 0x871dbc7394deb98
    .dword 0xfb61c5d318c347b4, 0x6b73ae9afadc4fd1
    .dword 0xf6992e76ca031f01, 0x64de65bb3ee265b1
    .dword 0xcea3e4b8bccb7583, 0xa4cb6e9e75a943b5
    .dword 0x6f1979de09b9188f, 0xf017497f9c9f37a3
    .dword 0x14a6bef51a6ab5d0, 0xabef797c4cab75ef
    .dword 0xcce9521086b68b01, 0x92731b2900d45b3


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
