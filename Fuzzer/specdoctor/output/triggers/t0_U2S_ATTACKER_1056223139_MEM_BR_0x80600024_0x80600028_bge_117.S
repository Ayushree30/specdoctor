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
                    la x21, data6                             
                    add x22, x22, x21                         
                    fld f0, 8(x22)                            
pfx.bb0.l1:         andi x21, x21, 0x3f8                      
                    la x18, data6                             
                    add x21, x21, x18                         
                    fld f1, 0(x21)                            
pfx.bb0.l2:         andi x19, x19, 0x3f8                      
                    la x20, data2                             
                    add x19, x19, x20                         
                    fld f2, 0(x19)                            
pfx.bb0.l3:         andi x19, x19, 0x3f8                      
                    la x18, data0                             
                    add x19, x19, x18                         
                    fld f3, 24(x19)                           
pfx.bb0.l4:         andi x18, x18, 0x3f8                      
                    la x19, data1                             
                    add x18, x18, x19                         
                    fld f4, 24(x18)                           
pfx.bb0.l5:         andi x18, x18, 0x3f8                      
                    la x21, data0                             
                    add x18, x18, x21                         
                    fld f5, 8(x18)                            
pfx.bb0.l6:         andi x21, x21, 0x3f8                      
                    la x22, data4                             
                    add x21, x21, x22                         
                    fld f6, 16(x21)                           
pfx.bb0.l7:         andi x21, x21, 0x3f8                      
                    la x19, data1                             
                    add x21, x21, x19                         
                    fld f7, 24(x21)                           
pfx.bb0.l8:         andi x19, x19, 0x3f8                      
                    la x20, data7                             
                    add x19, x19, x20                         
                    fld f8, 16(x19)                           
pfx.bb0.l9:         andi x21, x21, 0x3f8                      
                    la x19, data5                             
                    add x21, x21, x19                         
                    fld f9, 8(x21)                            
pfx.bb0.l10:        addi x18, zero, 157                       
pfx.bb0.l11:        addi x19, zero, 1127                      
pfx.bb0.l12:        addi x20, zero, 219                       
pfx.bb0.l13:        addi x21, zero, 575                       
pfx.bb0.l14:        addi x22, zero, 160                       
pfx.bb0.l15:        addi x23, zero, 1900                      
pfx.bb0.l16:        addi x24, zero, 1219                      
pfx.bb0.l17:        addi x25, zero, 27                        
pfx.bb0.l18:        addi x26, zero, 982                       
pfx.bb0.l19:        addi x27, zero, 863                       
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
prp0.entry.l0:      call fn2                                  
prp0.entry.l1:      fclass.d x20, f4                          
prp0.entry.l2:      fcvt.d.lu f3, x19                         
prp0.entry.l3:      and x18, x19, x21                         
prp0.entry.l4:      feq.s x21, f2, f4                         
prp0.entry.l5:      remw x20, x21, x22                        
prp0.entry.l6:      call fn4                                  
prp0.entry.l7:      sltu x22, x20, x19                        
prp0.entry.l8:      bne x22, x20, prp0.bb0                    
prp0.bb0:
prp0.bb0.l0:        xori x19, x20, 1836                       
prp0.bb0.l1:        bgeu x18, x22, prp0.exit                  
prp0.bb0.l2:        slt x18, x19, x22                         
prp0.bb0.l3:        fcvt.w.d x19, f3                          
prp0.bb0.l4:        fmax.s f3, f4, f2                         
prp0.bb0.l5:        jal x22, prp0.exit                        
prp0.bb0.l6:        call fn3                                  
prp0.bb0.l7:        jal x18, prp0.exit                        
prp0.bb0.l8:        call fn3                                  
prp0.bb0.l9:        fcvt.d.lu f0, x21                         
prp0.bb0.l10:       bltu x22, x21, prp0.bb1                   
prp0.bb1:
prp0.bb1.l0:        remu x20, x19, x18                        
prp0.bb1.l1:        call fn2                                  
prp0.bb1.l2:        feq.s x19, f4, f0                         
prp0.bb1.l3:        fsgnj.d f3, f4, f1                        
prp0.bb1.l4:        fmax.s f2, f3, f0                         
prp0.bb1.l5:        fcvt.s.w f1, x18                          
prp0.bb1.l6:        or x21, x19, x22                          
prp0.bb1.l7:        fdiv.s f4, f1, f2, dyn                    
prp0.bb1.l8:        andi x20, x22, 178                        
prp0.bb1.l9:        fcvt.lu.s x18, f1                         
prp0.bb1.l10:       bltu x21, x19, prp0.bb3                   
prp0.bb2:
prp0.bb2.l0:        mul x22, x20, x21                         
prp0.bb2.l1:        fcvt.d.lu f1, x22                         
prp0.bb2.l2:        fsqrt.d f2, f3, rdn                       
prp0.bb2.l3:        fcvt.s.w f2, x20                          
prp0.bb2.l4:        fcvt.lu.s x19, f2                         
prp0.bb2.l5:        call fn2                                  
prp0.bb2.l6:        divuw x18, x20, x21                       
prp0.bb2.l7:        fmin.s f3, f0, f1                         
prp0.bb2.l8:        fnmadd.s f0, f1, f4, f3, rup              
prp0.bb2.l9:        la x18, prp0.exit                         
                    jalr x22, 0(x18)                          
prp0.bb3:
prp0.bb3.l0:        call fn4                                  
prp0.bb3.l1:        fnmsub.s f4, f3, f1, f2, rmm              
prp0.bb3.l2:        call fn3                                  
prp0.bb3.l3:        call fn0                                  
prp0.bb3.l4:        rem x20, x22, x18                         
prp0.bb3.l5:        blt x20, x19, prp0.exit                   
prp0.bb3.l6:        fmsub.s f1, f3, f0, f4, dyn               
prp0.bb3.l7:        fcvt.d.w f2, x19                          
prp0.bb3.l8:        feq.d x19, f0, f3                         
prp0.bb3.l9:        bne x22, x21, prp0.exit                   
prp0.bb3.l10:       bgeu x22, x19, prp0.exit                  
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      fmin.s f1, f3, f2                         
prp1.entry.l1:      fcvt.w.d x20, f4                          
prp1.entry.l2:      call fn0                                  
prp1.entry.l3:      add x19, x22, x21                         
prp1.entry.l4:      fclass.d x22, f2                          
prp1.entry.l5:      div x19, x22, x21                         
prp1.entry.l6:      blt x20, x19, prp1.bb1                    
prp1.entry.l7:      fcvt.s.wu f3, x20                         
prp1.entry.l8:      fsgnj.d f3, f4, f1                        
prp1.entry.l9:      remuw x22, x20, x21                       
prp1.entry.l10:     beq x22, x19, prp1.bb1                    
prp1.bb0:
prp1.bb0.l0:        fcvt.lu.d x21, f0                         
prp1.bb0.l1:        fmv.w.x f0, x19                           
prp1.bb0.l2:        call fn2                                  
prp1.bb0.l3:        fadd.s f3, f1, f2, rtz                    
prp1.bb0.l4:        or x22, x21, x18                          
prp1.bb0.l5:        fclass.s x18, f1                          
prp1.bb0.l6:        bltu x22, x21, prp1.bb2                   
prp1.bb0.l7:        bgeu x20, x21, prp1.bb1                   
prp1.bb1:
prp1.bb1.l0:        fdiv.d f1, f3, f4, dyn                    
prp1.bb1.l1:        call fn4                                  
prp1.bb1.l2:        call fn1                                  
prp1.bb1.l3:        fcvt.s.w f0, x20                          
prp1.bb1.l4:        beq x18, x22, prp1.bb2                    
prp1.bb1.l5:        call fn0                                  
prp1.bb1.l6:        fnmsub.s f2, f0, f1, f3, rmm              
prp1.bb1.l7:        srai x22, x21, 18                         
prp1.bb1.l8:        beq x22, x20, prp1.exit                   
prp1.bb2:
prp1.bb2.l0:        fnmsub.s f1, f4, f0, f3, rtz              
prp1.bb2.l1:        fcvt.lu.s x19, f4                         
prp1.bb2.l2:        fcvt.wu.d x20, f4                         
prp1.bb2.l3:        fcvt.l.s x21, f3                          
prp1.bb2.l4:        or x21, x19, x20                          
prp1.bb2.l5:        fcvt.wu.s x22, f1                         
prp1.bb2.l6:        flt.d x19, f4, f3                         
prp1.bb2.l7:        add x21, x19, x18                         
prp1.bb2.l8:        fle.s x22, f2, f1                         
prp1.bb2.l9:        call fn4                                  
prp1.bb2.l10:       bgeu x18, x19, prp1.exit                  
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        fclass.s x22, f0                          
tc.entry.l1:        fcvt.w.s x20, f2                          
tc.entry.l2:        fsgnjx.s f4, f0, f3                       
tc.entry.l3:        andi x19, x19, 0x3f8                      
                    la x18, data3                             
                    add x19, x19, x18                         
                    lhu x20, 16(x19)                          
tc.entry.l4:        remu x22, x20, x18                        
tc.entry.l5:        bge x19, x22, tc.bb2                      
tc.bb0:
transient:
transient_end:
tc.bb0.l0:          call fn4                                  
tc.bb0.l1:          fsgnj.s f0, f1, f4                        
tc.bb0.l2:          call fn0                                  
tc.bb0.l3:          bgeu x22, x21, tc.bb2                     
tc.bb0.l4:          call fn1                                  
tc.bb0.l5:          andi x19, x19, 0x3f8                      
                    la x21, data2                             
                    add x19, x19, x21                         
                    fsw f1, 4(x19)                            
tc.bb0.l6:          la x21, tc.bb2                            
                    jalr x20, 0(x21)                          
tc.bb1:
tc.bb1.l0:          andi x19, x19, 0x3f8                      
                    la x22, data6                             
                    add x19, x19, x22                         
                    amoxor.d x18, x20, (x19)                  
tc.bb1.l1:          andi x18, x18, 0x3f8                      
                    la x20, data6                             
                    add x18, x18, x20                         
                    sd x19, 8(x18)                            
tc.bb1.l2:          fcvt.w.d x22, f2                          
tc.bb1.l3:          fsub.d f4, f0, f3, rne                    
tc.bb1.l4:          bne x21, x20, tc.exit                     
tc.bb1.l5:          andi x20, x20, 0x3f8                      
                    la x21, data1                             
                    add x20, x20, x21                         
                    lbu x19, 5(x20)                           
tc.bb1.l6:          andi x20, x20, 0x3f8                      
                    la x22, data7                             
                    add x20, x20, x22                         
                    sc.d x21, x18, (x20)                      
tc.bb1.l7:          call fn0                                  
tc.bb1.l8:          la x19, tc.exit                           
                    jalr x18, 0(x19)                          
tc.bb2:
                    spdoc_check_c
tc.bb2.l0:          divw x19, x18, x22                        
tc.bb2.l1:          andi x18, x18, 0x3f8                      
                    la x22, data4                             
                    add x18, x18, x22                         
                    flw f4, 28(x18)                           
tc.bb2.l2:          andi x18, x18, 0x3f8                      
                    la x19, data3                             
                    add x18, x18, x19                         
                    flw f3, 4(x18)                            
tc.bb2.l3:          fmadd.d f2, f0, f3, f1, rup               
tc.bb2.l4:          fnmsub.s f3, f1, f4, f2, rne              
tc.bb2.l5:          fmadd.s f4, f0, f3, f2, rdn               
tc.bb2.l6:          la x19, tc.bb3                            
                    jalr x22, 0(x19)                          
tc.bb3:
tc.bb3.l0:          sra x21, x22, x19                         
tc.bb3.l1:          fmv.w.x f1, x22                           
tc.bb3.l2:          fmv.x.d x19, f3                           
tc.bb3.l3:          andi x22, x22, 0x3f8                      
                    la x20, data0                             
                    add x22, x22, x20                         
                    amoxor.d x19, x21, (x22)                  
tc.bb3.l4:          call fn2                                  
tc.bb3.l5:          call fn0                                  
tc.bb3.l6:          slliw x18, x19, 1                         
tc.bb3.l7:          blt x20, x18, tc.bb4                      
tc.bb4:
tc.bb4.l0:          jal x22, tc.exit                          
tc.bb4.l1:          fence.i                                   
tc.bb4.l2:          fence                                     
tc.bb4.l3:          fsgnj.s f4, f1, f0                        
tc.bb4.l4:          slli x18, x21, 21                         
tc.bb4.l5:          flt.s x18, f2, f4                         
tc.bb4.l6:          remu x20, x19, x18                        
tc.bb4.l7:          rem x21, x22, x18                         
tc.bb4.l8:          bgeu x19, x21, tc.exit                    
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
fn0.entry.l0:       xori x26, x24, 969                        
fn0.entry.l1:       fsqrt.s f9, f6, rne                       
fn0.entry.l2:       fcvt.lu.s x24, f6                         
fn0.entry.l3:       fclass.d x27, f9                          
fn0.entry.l4:       srai x24, x25, 9                          
fn0.entry.l5:       fmax.d f9, f6, f8                         
fn0.entry.l6:       add x24, x26, x25                         
fn0.entry.l7:       fsgnjx.d f6, f9, f8                       
fn0.entry.l8:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       or x27, x25, x24                          
fn1.entry.l1:       fcvt.d.l f5, x24                          
fn1.entry.l2:       fcvt.d.w f5, x24                          
fn1.entry.l3:       fcvt.s.wu f8, x24                         
fn1.entry.l4:       addi x25, x27, 1154                       
fn1.entry.l5:       ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       fcvt.l.d x25, f5                          
fn2.entry.l1:       fcvt.d.w f6, x25                          
fn2.entry.l2:       fle.s x26, f6, f8                         
fn2.entry.l3:       fnmsub.s f8, f9, f6, f7, dyn              
fn2.entry.l4:       mulhsu x26, x24, x27                      
fn2.entry.l5:       fsgnjx.d f8, f9, f6                       
fn2.entry.l6:       srli x25, x24, 48                         
fn2.entry.l7:       add x24, x26, x27                         
fn2.entry.l8:       fmadd.d f9, f6, f8, f7, dyn               
fn2.entry.l9:       fmul.d f8, f5, f7, rmm                    
fn2.entry.l10:      ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       fmsub.d f9, f8, f5, f7, rne               
fn3.entry.l1:       mulhsu x24, x26, x23                      
fn3.entry.l2:       fmsub.d f7, f6, f9, f8, rdn               
fn3.entry.l3:       auipc x23, 1170                           
fn3.entry.l4:       fcvt.wu.s x26, f5                         
fn3.entry.l5:       slli x23, x25, 45                         
fn3.entry.l6:       fsgnjx.s f9, f6, f8                       
fn3.entry.l7:       fcvt.s.lu f5, x24                         
fn3.entry.l8:       ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       divuw x23, x26, x25                       
fn4.entry.l1:       srli x26, x24, 63                         
fn4.entry.l2:       auipc x26, 148                            
fn4.entry.l3:       srli x24, x27, 41                         
fn4.entry.l4:       flt.s x25, f6, f8                         
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
    .dword 0xb034c1cd05cf18f4, 0x79899e87d6d44c3c
    .dword 0x2b478c4ae09ccee9, 0x1a1523be6dbb50f0
    .dword 0xf860a66b563a709b, 0x1d339141b42591f4
    .dword 0x779bd5feed6ad7f4, 0x631e38409085225d
    .dword 0xc0bb6cf044e68815, 0xabf1a5132aa85b44
    .dword 0x5c1b82cc5927813e, 0xf794054a1eb16d4c
    .dword 0x11d251f9aaf05f58, 0x871d7f54da560fdb
    .dword 0xb8103fbb892c4088, 0x161b1aa0ed5dd49c
    .dword 0x672c7c35e5e4625d, 0x7bdb0e641edd4dad
    .dword 0x9c628b4b8958e4d9, 0x5cfc333131794b69
    .dword 0x65893a0103db47e7, 0x27954d2bcf041169
    .dword 0x7b8f63cb7324d260, 0x910d8f6be6619cb5
    .dword 0xc310e9976af7502b, 0x91aa758013a45ed2
    .dword 0x9f7372fc4f56bbf1, 0xe5621a329ba1af9a
    .dword 0x325a56feb1270689, 0xdebca054e0cb8188
    .dword 0x11ba660d465a49d9, 0xc019357b2f38f1d2
    .dword 0xa049ad1eed19d16, 0x9978cac238b47fc9
    .dword 0xb33830a6429c9401, 0x49f91777f6ea8682
    .dword 0x944e3f8534ee89fe, 0xd424db68bd72c653
    .dword 0x343cb1e05cccaca2, 0x24be53eb92234434
    .dword 0xd918fe1d5e97f727, 0x34cf0674f4f79ffe
    .dword 0x75561db5e3dfcaf4, 0xfbbae75663935d77
    .dword 0x62b19bca60e355b6, 0xf91a5e79f0918f42
    .dword 0x4f3e5e33340fa081, 0x7a176c4c11859d45
    .dword 0x46d618dd5a3ffa30, 0x4133ac035fce5aaa
    .dword 0x288824171fc9f6cf, 0xb8aeee8d3e3000b9
    .dword 0x112ff7bcac1d5565, 0xe13a1495aa25d042
    .dword 0xce2d79ecf1adbe61, 0xe77b20c61197ecc5
    .dword 0x7c41e878f31fa550, 0x45f333ee3034964d
    .dword 0x50aaa3e9c1591c56, 0x5356a1bd29c911b1
    .dword 0x47b939102c9cf2b7, 0x18bb69ea2d6c0bd3
    .dword 0x74f94589ebc8e7db, 0xc897c0dd5961484f
    .dword 0xcda77d6eca98d034, 0x1fac5ee3677634d2
    .dword 0x6dd625f02c821775, 0x254e559f02fcc151
    .dword 0xae3810a606b6f93d, 0x6b63675f54286d48
    .dword 0xac71c2b2221f3f91, 0xb8d14dce5e0e9dbe
    .dword 0x8e9af82a5b2dd57d, 0x2730653f5b7fc1e9
    .dword 0x9ce6f39b155a1bf6, 0x8cd0f2fe2f5f6057
    .dword 0x4225663883a942ea, 0xdcb65e137a6ee5fe
    .dword 0xc061a46e987a30f9, 0xdad2d31853a74af6
    .dword 0x3e7694295da70bcb, 0x4010a659bd228bfa
    .dword 0x703e8f2f699bad04, 0xe5949105205a0fb1
    .dword 0x38185fe0b0680403, 0x2c232d7d791ab8b6
    .dword 0x46bf8521b419c77f, 0x26a9c9d874e56c8
    .dword 0x6db49b87d98156af, 0xffb916a783df04c8
    .dword 0x94c55c296c02304f, 0xc9d16bc62cf3419b
    .dword 0xba0b49eb7f1e5a90, 0x791cc2131b65cfed
    .dword 0x301c473dce57b962, 0x282882ac2d07ff72
    .dword 0x7376d4aa8e36e82e, 0x6dacb64d6fef7bb2
    .dword 0xc4e3fb622e639bf9, 0x2671dd698aea2f8f
    .dword 0x2bc0d001feb2538a, 0xced4d5bac629e8bc
    .dword 0xa9985819c5ae908b, 0xa4193313350c6d61
    .dword 0xf0f929456797b652, 0x6d900acd7be477df
    .dword 0xc076c1b5d81d7e5c, 0x7718b861e6b83436
    .dword 0x8c24f62ab10ad6dd, 0x7a9cad7132886703
    .dword 0x40f73f5fa6719938, 0x640b5be43282d1cc
    .dword 0x11196e038a103bc4, 0x38605aa2a71805a2
    .dword 0x4df61c3b91fc412a, 0xbb6479e156e6d202
    .dword 0x1c1d265d616963c1, 0x3b9d14a5a848ec0a
    .dword 0xe800a10666447bb7, 0x785d64cbab2af07e
    .dword 0x80f83d3cd77d2126, 0x1ef00d6abe7a1ab1
    .dword 0x6f6ce59dcaaf8703, 0x7fd069beefd4ee24
    .dword 0x535fb8a229eac452, 0xa66b078b9ecee1a6
    .dword 0x2ab805e2287e9125, 0xed44ad87feb4b259

    .align 12
data1:
    .dword 0xc51eec495d99b31, 0x5152280adf75c392
    .dword 0x83053f49af6f02da, 0x2887dbbb49b7c685
    .dword 0xea90cccd74bbc5b, 0x4e9526bc54745e2f
    .dword 0x622e28a3045518e0, 0x9237b9bc0780792a
    .dword 0x6d5658602a99719, 0x6dc392e806da63d2
    .dword 0xea7148db94b713bf, 0x7bf75509bdbd3e52
    .dword 0xfe4660d53920788, 0x22037fec9ec460f7
    .dword 0x338f4471f3358151, 0xfe3449293133241
    .dword 0xa04cd936024a6a4, 0x5859816abfdc7d6a
    .dword 0xea9d841a62c312d, 0x90e7cf48490583a0
    .dword 0xa972a439f77e759, 0x8520bdfbad1290c3
    .dword 0xdbd7160c7ffbd76f, 0xa0990d98937d5798
    .dword 0xe948f1ffbadbf1a, 0x9074fc796236e682
    .dword 0x7ae62ee448f03b87, 0xe26766502d639c21
    .dword 0x638f8d065a6b5efa, 0x7150b03017f717f8
    .dword 0x5b1716a972116942, 0x2586234c4983f5e0
    .dword 0x1c7d708bfa415583, 0xf3549f8d510191d3
    .dword 0xbc321b4f94c7eaa9, 0xef22315824114875
    .dword 0x7fa6e7150fa3a512, 0xa607bffc61b669f7
    .dword 0x1892272fe18e499c, 0x114edfdc70c26406
    .dword 0x214be13139f00a39, 0xbd762a8fa3f5203f
    .dword 0x6683d565596e30b9, 0x96eda92d8b003509
    .dword 0xe12c80a24029d3c6, 0x5bafbdfa60321ed3
    .dword 0xd4e126819337dbe2, 0x53ed8fc66ce35927
    .dword 0x236c1e6d732e0a80, 0x9c79168070e37082
    .dword 0x88ed5ac851e68560, 0x56674b1838e19755
    .dword 0xa73ed14de57c1e4d, 0x758f09a12cd01cd1
    .dword 0xb1465513a3861517, 0x3a9857bdd732b7c2
    .dword 0x9f26f491c6cb465d, 0x189e5b3e61b20a58
    .dword 0x4e9f09d9a82425bf, 0x8c17a02dfc0f4fc6
    .dword 0xba6a1e6ffe38a2f4, 0x626e6501c753bc9
    .dword 0x979ae2ece2b0fc64, 0x50d354192bff00bc
    .dword 0x82cec7a93a7965f8, 0x402898a45c3b0de8
    .dword 0x9c52940d713ccd14, 0x751c54a14ab44d9
    .dword 0x53d66a11e98fc3d, 0x52f31e7bb1f42f36
    .dword 0x7b5af5f9a71f63d8, 0xcc4decc21ea5db88
    .dword 0x100afe1e42cab3ac, 0xd9b21d4f3d12cd7a
    .dword 0x3a7a8a9235b4394d, 0x3a06690c739106a0
    .dword 0xfcb6a48bc6bccf5, 0x953813fffed47e8b
    .dword 0xacd580fb21bfac27, 0xf043f3165fab3f7a
    .dword 0xe0b9173efc5726b5, 0x5913ffc0ee2a5980
    .dword 0xeb4a92bd05ab38e6, 0x23a4182ce721fb7a
    .dword 0x2296df327ea32323, 0xe4e168e3cc32b94f
    .dword 0x632a3e208896facd, 0x71666fe42eaf3f3d
    .dword 0x9681432eebaa5762, 0x3d7c078642193bb6
    .dword 0xcdee9421b23bd93d, 0x25cae0e05e32c90f
    .dword 0x48c00592e51198fd, 0xf95c8983779ac5fd
    .dword 0x5288301577c9f5cd, 0xf53f8a3eb8c6c801
    .dword 0xb657fed5600a303, 0xc61359cb2016e072
    .dword 0x74f4978043e81dac, 0x852317b9a9fec2fe
    .dword 0xad7919a6d5af6139, 0xe129e8d9734d995e
    .dword 0x914d7d911294014b, 0x83519a6ef7b41242
    .dword 0xac922c01243055e2, 0x6e9b250fe681cd1
    .dword 0x3cc5ef92c7a6e560, 0x9b548357f22687ed
    .dword 0x3355a7748c62a653, 0xab9c88b223e05c70
    .dword 0x9c6e4c6d3222d1bd, 0xf9d024da957fcf6
    .dword 0x7e7067f195987123, 0xf8f34e35541c6a69
    .dword 0xe59aa61f133dfe54, 0xdcb72ad103cb827e
    .dword 0x30172f4c4d7f4918, 0xec22f0c96fdd099c
    .dword 0xc4e8f1c25828b44, 0xccec91cbbdbc5b2d
    .dword 0x45a30684d0b065e, 0xfd6f3e64e60a953a
    .dword 0xc0797f988d90a41, 0x8f21e4bb80e60faa
    .dword 0xbb0a6bf3a5b5f25d, 0x1ca96d8bd0d31984
    .dword 0x26b3d3074124cdd2, 0x59ee57d3043a6843

    .align 12
data2:
    .dword 0x9d30484770ed722b, 0x428464e0ee4fdd16
    .dword 0x4663ea05b8fde03c, 0x6003f9e2e035ac07
    .dword 0x298c1b9d4f7701f1, 0x69c9170917d38bee
    .dword 0x4e75b88aa5e27cb0, 0x4c706fd971606603
    .dword 0xb1b1abb612359b84, 0x8d1bf4831f67be1c
    .dword 0x31dd6eadf6128d63, 0xd59e8d35dc69bfde
    .dword 0x21d376d4392394ff, 0x54240918fd9937f5
    .dword 0x66c6f47c5d7100b5, 0x27752739854934c
    .dword 0x70d23806adb58ac0, 0xc9f433ae274308f
    .dword 0xeb32c49fb8262d61, 0x160e09164613a985
    .dword 0x4345a2a504820600, 0xcd05458cb43f0b8c
    .dword 0x18986dd52609e724, 0x4692f8f39a9af44
    .dword 0x5b8e6cfe9d7c0ceb, 0x3dbff457195bb48e
    .dword 0xbaa280b2537a9e37, 0x15d915e517c8e6d9
    .dword 0xae51e2ae217ed53e, 0x8214f3612065c055
    .dword 0x364401eaf07f0978, 0x3a9e2c2190d5cd25
    .dword 0xe0ae7bc491c40b5e, 0x8d0cbc2d89ae2fd
    .dword 0xfbbac45f4523c36, 0x5539babe9994db26
    .dword 0x8e0af607b6646e17, 0x3408e885b3910d4f
    .dword 0x433de1be9121f6de, 0x2b3e4d3d08a33078
    .dword 0xdf31e98f9b4e6307, 0x471a862f5d9d7da
    .dword 0xdf2a26b6fde0a896, 0xabddcaed30e224ed
    .dword 0x7069b0f3e975291b, 0xac98d4be9c9d7512
    .dword 0xd851d2cf16754906, 0x6de354b81d36a011
    .dword 0x4cc7e82af9abb020, 0x8343005e7aa09365
    .dword 0xa0024e7b78b05c84, 0xff55a7c9da74cc3a
    .dword 0xb4005c0e0a1c2a91, 0x83284d68a30990cb
    .dword 0x5fd497e6b48fb8a6, 0x942dcda3c749fbb3
    .dword 0xffc2b0940a2a500a, 0x9ce0f95f90dfd23f
    .dword 0x46ebd33d92abc050, 0x4a0a48266d8a2983
    .dword 0xfbfdc1c51164c227, 0x80af6e92f6706694
    .dword 0x8ba219eca8d72c11, 0x1ccd5dc5d00dbe83
    .dword 0x3c13eb5d1b741565, 0x69280f73f7a3eab2
    .dword 0x63fdbc76f9ce64d5, 0xa0d60b5dc582151f
    .dword 0xd445f67c374e946a, 0x4f8b302841ebc96e
    .dword 0x7b88e74d31d950a, 0xf92ec9fce97646c6
    .dword 0x68680e27f91e305, 0xe91b4d8b419bb08e
    .dword 0xfa3f106d97afc3ce, 0xa38ecddc17e1bcaa
    .dword 0xca46f86473aedff3, 0xc811e1eec03a185d
    .dword 0x50ecdd36e244deaa, 0x1283be0bb32bfdb8
    .dword 0xf510bb208fc765f5, 0x91e1e3c8c5f739cc
    .dword 0xd12f022ef323eed8, 0xe462e08414cfa841
    .dword 0x974860930139e296, 0xdae7f206f5121ac3
    .dword 0x1de1e5c3691c7a06, 0x37ef58d22542abac
    .dword 0x60c724c26b70f2ea, 0x6c76a6f368bd719e
    .dword 0xb363511e4032ad7d, 0xae189914a07985d5
    .dword 0xd0369b0e4a6f70cb, 0x4f8958656fb4192f
    .dword 0xc55c657fdb86f358, 0x8c81a5cd8c93ceee
    .dword 0x1e0bfdaab9f3ec9c, 0x36bcd81107e7a23
    .dword 0x78f5d433dadc4bf2, 0xf8ac08513f92c84f
    .dword 0x2517f96841fe0f2b, 0x2e64ffddbc9b903c
    .dword 0xb221f7bc77dcd8a1, 0xa45fb0e934e801c0
    .dword 0x74a119a58ef9d9ed, 0xa3e5f0cb53f06327
    .dword 0x5cfa779a296c61c, 0x21b846b6dbcd6381
    .dword 0x476a88daa7d296de, 0x7365197e4c1298bd
    .dword 0x2b5fe5be0ddb9f31, 0xaef59f090c789e2f
    .dword 0x753286e8d1709ed3, 0xe45ac7a514aa245f
    .dword 0xa247431396d9d872, 0x5dd580297266190d
    .dword 0x11495adb1a2fae69, 0xb59a6421be95a8be
    .dword 0x95c9217ea822854b, 0xd3455b7b260d60cb
    .dword 0x3b1395fe4b0ac8c0, 0xfcee46d722860345
    .dword 0x53c070d40c3f8a94, 0xd76bea8d507a4a43
    .dword 0x18e525567cd4b8c2, 0xef3f35e1a24ac1cb
    .dword 0xa0ad40eb15ed47f5, 0x8c8b437d0c1119b5

    .align 12
data3:
    .dword 0x8868e0d686a18f88, 0x7a96046234e39fbb
    .dword 0x3c3b29cd4db2e8b7, 0x9ec0c5f2cdf5efcc
    .dword 0xd9ec58978d042e0d, 0xc55c3aa9d5ff3d9f
    .dword 0x951089ee40a774f, 0x6365a2a1b12a245a
    .dword 0xd2d074eecaa093eb, 0x567cd1f9bcfa83a7
    .dword 0xcfa83f949efdf7ca, 0x8b231c1865a85509
    .dword 0xd535a3d5a7097bc0, 0x6b121386ae42d714
    .dword 0x52d37724291b8957, 0x72e4b782cf5bf845
    .dword 0xfdf2c0bf9d2768f3, 0x1f42b13f1f31b1d1
    .dword 0xeae8268c0428d6aa, 0x8b6f96ba54200e5e
    .dword 0xcb233b71bee4bc17, 0x37729dff5b232067
    .dword 0xee3f76177528f57e, 0xea79b73a83f82165
    .dword 0x7ac89b64b45bebb7, 0x66af7ae9da818d3d
    .dword 0xc7c59a7a3eed1321, 0x294af7e5aa4ccd0d
    .dword 0xa35a47070ebdfa97, 0xbd35b2ea7563ac3
    .dword 0x285dc696c9a43b8b, 0xf02abb18418e6c7
    .dword 0x7b2dd800aaa634f7, 0x8a4af8112eb6e67c
    .dword 0x2a714619aef93efb, 0xdf281d7461e63a0d
    .dword 0xcd698956233f2846, 0x982ddee73673e950
    .dword 0x34d8b98d97cbeb91, 0x2255cf8b9917d770
    .dword 0xd91d8006fd5d3483, 0x2b3631ce8736d3b0
    .dword 0x1857becda2da18cc, 0xc080d23abb735593
    .dword 0x1590b5ce35c8669e, 0x2ebf570627cdea35
    .dword 0x81d88f36fe483134, 0x531bfd0735585ed9
    .dword 0x5e81b7713a03a393, 0x406c8296634cbd18
    .dword 0xac9b8bbe9bb453c2, 0x57c4201194d1bb30
    .dword 0x261a0e8e0304658d, 0xf45ab58579cfe282
    .dword 0x26a89bd848bfb07, 0x28fce77f5cab654f
    .dword 0xca26d163a6e77937, 0x9ff33c5e8209e653
    .dword 0xfa0ac86e3d1413d1, 0x69b86b5fd12ce16f
    .dword 0x40b91824b088923b, 0xcd2b9f6a4e27ab8c
    .dword 0x6ff19cd87438388f, 0xb6d4bb9a3febda71
    .dword 0xeb39ccaa696f5842, 0x5eb5dd5a2d383466
    .dword 0x8fc7ad5825a2dc1f, 0x780c57606bca8dbd
    .dword 0x4cf19100545450d8, 0x9220e4b42cf29c39
    .dword 0x3f59bbe3717060d4, 0x1f93e429c5a577a
    .dword 0x95c2f83ea0944233, 0x1654cd0ebba80745
    .dword 0xd0eb44c996dc2b51, 0x296ee43e5f1f9ab1
    .dword 0xdae475fd48a4e7e4, 0x866bd4442810cb10
    .dword 0x7697dd60bdc8d43f, 0xb14bc576fcef912
    .dword 0x404e2362adb32821, 0xbc8e205e4f248be5
    .dword 0xe990c3b20f808506, 0xe72f0abdefe4df98
    .dword 0x8a2847b1283d0c61, 0xbeb742e1575083b8
    .dword 0xbb1e29dc88763258, 0xb1f2345814a2d8fa
    .dword 0xed911694b8299cb2, 0x257ff07bf7c980d4
    .dword 0x860b8e132183ed6d, 0x135584fb2ee371b8
    .dword 0xacae78cdd3f67c33, 0x17807fe3b7fe87e1
    .dword 0x2044b0965c3fd2d6, 0x8e9ab2e0c3fbe3cb
    .dword 0x4c92bf42e4c5cb3c, 0xe1026d0a5d7c8197
    .dword 0x45cb18c846d64998, 0xd05b2e8bb58441c3
    .dword 0x18cd01f7295b45c3, 0xa66ba711799dcd2c
    .dword 0xecfe6fe6bc824e26, 0xf05444feb2295d6a
    .dword 0xc83c325234f44c69, 0x856c674c3d4e69e6
    .dword 0xc1296fd69839abfe, 0xc4838cf5cf159f10
    .dword 0x723b8cd850bb2873, 0x6b757f133745d510
    .dword 0x44c3c01f06f56734, 0xf8e4f183bd4072a4
    .dword 0xa1dde2a5029bf803, 0x82c03ff2e2ab67cf
    .dword 0x506b8f3098b3fe7, 0x591f05ae56b2abf9
    .dword 0x2f4fbceafb6132cd, 0x35dab92a407fa793
    .dword 0x63133faa0249dd35, 0xef65afd4abe52b18
    .dword 0xae4ae38a20e45dd, 0x89f62956fb13497
    .dword 0x8030ce32a895a943, 0xfefa9c393d6d9fe6
    .dword 0x8281fa99f809d05e, 0xe971dc7a673b8f52
    .dword 0x340a8799ed9b3efe, 0x6951e726b3d817bf

    .align 12
data4:
    .dword 0x725a7a0ee1ec1e01, 0xe83dbb40549c5029
    .dword 0xdd01bc3af8202b61, 0xd76f4acd9599b18d
    .dword 0xdfbe0eeed606d3a3, 0xb9fbe960e9242595
    .dword 0x8b03679403a7041f, 0x2a287a8d116aec0c
    .dword 0x16a30b1d9b2975a3, 0xe03ab42e266b4b46
    .dword 0xb18642a3f99feae8, 0x757265120a154169
    .dword 0x82827526e1636025, 0xea7fdacbb4b08f47
    .dword 0x4d9bfcec9d934ebf, 0xb4d53b9a4fe42a14
    .dword 0x238803a311f723bd, 0x52cc4744d87ce1f7
    .dword 0x2986ef55b3d9eb01, 0xfc6615aba8f6493d
    .dword 0x2cbec3cdcf37ee16, 0x7c4deb0e60b3e809
    .dword 0xd188e42d5ee27394, 0x21feccd617e03c8c
    .dword 0x7724c80e450f07d0, 0x77ff984641ce84b0
    .dword 0x10d218a55e0981be, 0x72f11dbb3f08d96e
    .dword 0x338bd3c0f3901cc9, 0x5ab0e4205fe7786f
    .dword 0xc546d31276c852f2, 0x9eb17660bfb073f4
    .dword 0x3f70fc31f77c1de4, 0x79ce765bad5ea27c
    .dword 0xf07d8b852c7bfab7, 0x5489ebe148be9708
    .dword 0x4ba55ffcc46858b3, 0xb23a8111c41dd60e
    .dword 0xdf561101895a225c, 0x195615c96793b7b9
    .dword 0x6d3a593c18741bdc, 0x2b0391ec3813d537
    .dword 0xfbe0ee1e399a066c, 0x6f58d018b473bf4
    .dword 0xdbbef7da2d52a89f, 0x9e8ac93c03390ef3
    .dword 0x36037d7a976a9fa4, 0xa43e5bf5b817cf3b
    .dword 0xb3f4949ffdebbb0, 0xad33f9487ba67ae5
    .dword 0xf9429dcaea039e7, 0x7e2d801ce7bfac7
    .dword 0x38f5911d3c60962f, 0xa404fb4c556068cc
    .dword 0x3f424db3fffc5433, 0x38700dce2f038e26
    .dword 0x2da145ed3a7acad6, 0xaf2015b956567b11
    .dword 0x97990fd0ef95f721, 0x47ccc68bc89697f8
    .dword 0xc5f8048c2295698a, 0x70c3d6f3557130a7
    .dword 0x210666b34fd887bb, 0xe31d8a7eb4458c40
    .dword 0x8732eafbf34cec37, 0x9f5ec19f27ac3083
    .dword 0x2e4141fd7780d7e5, 0xbbf4acdfa0de7ace
    .dword 0xccbb5acb04d24093, 0x183855faa1b58ed3
    .dword 0x1cffa1dc414a498a, 0x6d594841de7f4e07
    .dword 0xc7d027658645147f, 0xb1e595d97602eb7f
    .dword 0x1fd2cfb3d817e966, 0x10a8d4124fb9183a
    .dword 0xa647a5ddb9608593, 0xf037882af979a392
    .dword 0xaa2a1e9f2c5bfb0a, 0xa001dbe0245ae81f
    .dword 0xf4ac25bdb947cf2b, 0xc4cc8751dcb71529
    .dword 0xaa9affb0e9ccc293, 0xb12e5ce73867db7
    .dword 0x88f51fad1ecb081d, 0xfd2ef3f47f39c702
    .dword 0x91e06c61c6392b10, 0x8be5c2310b5e43e3
    .dword 0x83502a9841680d18, 0x5e6e041fc9d02026
    .dword 0x100d1ad091fc5aa3, 0x7df2d6a53907e184
    .dword 0x6722ec4ea70950b5, 0xd60e82d6bb187c96
    .dword 0x13e6f4acb580730e, 0x3d0e643fe80c2b26
    .dword 0xea5b4f172dd3e6c3, 0x91468487285f8f1f
    .dword 0x3f80321f58a6144f, 0xf20e455a1e8e419f
    .dword 0x1e264d88545c1f7c, 0x62afc7a298a9f33f
    .dword 0x4660a7a08b40d051, 0x38a8f780b8efd31a
    .dword 0x8520cb91cf42b106, 0xe962c205fcb17b94
    .dword 0x2e909bc20da13451, 0x4177224bb4856e8a
    .dword 0x3871338a498cb9c9, 0xe20bef435a002463
    .dword 0xfb7f39bb43cd8f72, 0x618eb3ce4b6dddf8
    .dword 0x3f879c2f55df3d8c, 0xc9968dc492d5caad
    .dword 0xf98e3b4fb13e55a4, 0x3788b5f262436ef9
    .dword 0x824e2178c74ffaf7, 0xa2b06b1ce3c2d96
    .dword 0x2aeeeb5a49cb9f48, 0xb4c3e6fdfeb9175b
    .dword 0x890601353a08fe4d, 0xa8e87246d50288be
    .dword 0xbb63541521483368, 0x8a0c5f1d340f84e4
    .dword 0x6dcbc099c3cf81cd, 0x3255c1f601237372
    .dword 0xc62ea79be7707f40, 0xd32c6926ef3e28a9

    .align 12
data5:
    .dword 0x476fb04307d909a0, 0x2b09766e68aaa851
    .dword 0x2c57062f8c028381, 0x9daca9285569cec1
    .dword 0x9f69aba1db2f60dd, 0x837ea9f898b0aeb6
    .dword 0xe5ce76b48f285e90, 0x7db55a14ac275364
    .dword 0x91f6ae7ccecc3ed0, 0x624e6d871f2e4e5e
    .dword 0x4bd51044472c0e50, 0x8d1a8bd9d1a8d7e0
    .dword 0xe536f74ae8f5da2, 0x929d616365dba365
    .dword 0x8682dc686ee98076, 0xee34c21c2bdd3827
    .dword 0x2b9f06872a90481b, 0x94e4bd435385f8a5
    .dword 0xc8e8074476272392, 0xb1675636c73f986b
    .dword 0xf6a1737b1c2ffb9c, 0xd43ff401f6af2b
    .dword 0x365b4086430210a9, 0x4021c7428ce3daa6
    .dword 0x8ad84d1452394918, 0xac925fe5878d1890
    .dword 0xbc2a5ac2c6e9592a, 0xacdbdc8e2aed83f0
    .dword 0xcfa19a6b2fe4e5ec, 0x69ba4621eeb12e96
    .dword 0xdddc02da1afac7d1, 0xf5a1c4b2c26d855e
    .dword 0xaa1de5fceded0ecd, 0x91614b7d4c922b93
    .dword 0xd1d44bf373442856, 0x78adeb0746c1ce84
    .dword 0x10874f4fc69b3147, 0x65f1738645943a52
    .dword 0x6b1a67932127c858, 0x80b635684c72ba39
    .dword 0x495647f29423d4a2, 0x5ae939a7dd2950a4
    .dword 0x8a6423492579f69e, 0xf6f5163b68ea51b5
    .dword 0xdacd5f93e50e1e6, 0x430d46dd75aea0bf
    .dword 0x76356ef44e955c2e, 0x1fa50bf325525ce2
    .dword 0x8f3105d370e70bcc, 0xcee4cd2ec96d0d34
    .dword 0x4d5afa5921838f94, 0xe4ab045087d37405
    .dword 0xdd6ca9ae32569b4a, 0x52549868752f9ec7
    .dword 0x11a8df25b89fd7a, 0x4e71dc9c8c81f0f0
    .dword 0xd91307b6a6ee0cc7, 0x3ad9e2188ffd0227
    .dword 0x9259ca8947c5d5d6, 0x523d9e000290a055
    .dword 0xe4529951f706e0, 0x65ce228f9f919904
    .dword 0xbb12c982234f9cd3, 0x80e5288bc005dae5
    .dword 0xf518c0f26779f55d, 0x235e6eb2cce4a957
    .dword 0x7d702a760ae1a1b, 0x49a5e8448549d808
    .dword 0x650b986b60d6505a, 0x24752357f9511f8
    .dword 0xbecffdbdf5134e2b, 0x87a0096c1417af99
    .dword 0x2031621da86ddc9, 0xf93abed008db2dbf
    .dword 0xbc21379f05219d8d, 0x6c58551167838355
    .dword 0x504a228609d0c8ab, 0xc3572e3db8cecec9
    .dword 0xe945871192bef55c, 0xa5754e31e6c6dfe3
    .dword 0x7c26fcd41be9db98, 0xafd860a08f6dbbf7
    .dword 0xfb52f9a34906365b, 0x2d8bfed01b1cd618
    .dword 0x4257a59b2a1812c0, 0x4e3ae0d06d2b2cd
    .dword 0x594485b2cad48200, 0xa6a8879441c172d8
    .dword 0xafe1196b1e9b9fa2, 0x237349b3b8ac8714
    .dword 0x63c735bb4cacb681, 0x185621e8f34361ba
    .dword 0xc9c5ee6e27ea403c, 0x427568cd97dcfc44
    .dword 0x8761c72b7bd77b09, 0x411f793e83b7888f
    .dword 0xb803dd23e65f95bf, 0xe2ebe4a023b236e5
    .dword 0xf76d8f5646af424a, 0x69fded57a23ab8f7
    .dword 0xbc64f048a9d9ca96, 0x64112ef677f66cd1
    .dword 0x248ca9ac4b168888, 0xa4567aa42648795a
    .dword 0x3b2737b6bd26b4d5, 0x5b6bb41531f5ce3
    .dword 0xa530bb811ba58876, 0x21a8b8e9f1464fe6
    .dword 0x95003480aea83541, 0xf2b4668d634906cc
    .dword 0x4dc29cf1219bbf8, 0x293bf5a0275946fb
    .dword 0xa23001af8b26fa07, 0xd9c100e3f6fb79da
    .dword 0xb35513c0c770b19a, 0xff9fb9eb98bf2b45
    .dword 0xa4157b2672072780, 0x857c5673f421dd86
    .dword 0x1238c55b4d845e75, 0x44ba4eccc6a29a21
    .dword 0x7e3123c918d22b4c, 0xd32bc024b768a77e
    .dword 0xb2ebadee1eb2f0c8, 0x95e044379d10f684
    .dword 0xe64ed881f549d7, 0xa8eedefdc664a66f
    .dword 0x84f635574d426410, 0x7c62ff31626356f1

    .align 12
data6:
    .dword 0xb857b67fa592008a, 0xf5ac36e166314073
    .dword 0xeb3e44749d09267, 0x16e3d60d96d013c8
    .dword 0xe1c25f4c756af87c, 0x8e05852c9870803e
    .dword 0x1cff26fb569288f8, 0x3e74de5c49c760ef
    .dword 0x1b23e47b0cbcbba1, 0x5f179e31e4614011
    .dword 0x1ae9025639725676, 0x62a58498eca7a2d4
    .dword 0xd9ac83eb2f855ca4, 0x94c2f3322b85eee0
    .dword 0x8aab4e6cc21ee01, 0xdc9b0bce070c8385
    .dword 0x903f6e0c22c6778d, 0x2ef611d832723813
    .dword 0xcd5a25295e224e9b, 0x7eabc6f2903c2715
    .dword 0x283264c2df0c59a9, 0xef2c8117387a6bf5
    .dword 0x64256e042eb8dbc1, 0x17dae76e455e7986
    .dword 0x20867e31119be2f6, 0x50e08a9508114753
    .dword 0x37b8658574818ecf, 0xb58e897a0972cf9
    .dword 0x4a827755fb1944dd, 0x7339629fd4d3a956
    .dword 0x1d8561609eb634d9, 0x15bb8d9edf2bd572
    .dword 0x16d906ed600c67d2, 0x1ffc349ff35ce4b2
    .dword 0x74b7a999d1ef93de, 0xc9c9a9296d39ba93
    .dword 0xd2bad88b7fbb1d7a, 0x37cf66141824f91b
    .dword 0x132c164b32ecc71e, 0xe428f498eb728636
    .dword 0xd768f69c04246cae, 0x5574ddd61b7dead0
    .dword 0x48eed54ca2bdcb07, 0xec7feeef402f7582
    .dword 0xea9f5d396c1023fe, 0xb8a71a4044d992aa
    .dword 0xbde33dca0f7f9236, 0x402e8d98d869bc56
    .dword 0xd8012b94a6449c51, 0x1c4acbe013cf1120
    .dword 0x15a65b22afd7d3ec, 0x67e49c525a0e2c3e
    .dword 0xfdcd954dc8bc487, 0xb08c8533f43e93b7
    .dword 0x34a2ad71788a390e, 0x3c4a18b510597ab2
    .dword 0x905cf674ae3b5ba3, 0xdc695f934b357268
    .dword 0xe799fa0b6b3ce8e, 0xf5b180c3f55dc08c
    .dword 0x2bc4f7fc60dcdcac, 0x773319aa895a15e9
    .dword 0x9d2237acce8c9d5e, 0x46bbe321b52d2cc
    .dword 0x5d96999164e65a6c, 0xf86535e2a55ac080
    .dword 0x418cbf2ba1c3f8aa, 0x8f136ede8567ea81
    .dword 0xd1bf8fbe6f64d8ee, 0xb34e59dda87eeeca
    .dword 0xa310b2b4de311508, 0x485deb0e0cd0c102
    .dword 0x1bf6723468cfc105, 0xeb11b3189ff4bc3a
    .dword 0xf84bde1958236788, 0x4fc25e638498da2c
    .dword 0xb8dae991017517ed, 0x5c71609f2d045d6f
    .dword 0x5e60e5f9ad06eba3, 0x9e67c5b4cc171a72
    .dword 0x375631c2c0056cd4, 0x45ce383bbd7cd7b5
    .dword 0x9f133d674efa32df, 0x16211f2e0e692748
    .dword 0x6eb03e2e7316f360, 0x3b862c3ceff07b8d
    .dword 0x7ec2ee94b383b117, 0xe1d83cf82cc0977d
    .dword 0x3fc2857c156986ec, 0xcf445b43f0a279b3
    .dword 0x651efb7a64924a5c, 0x7e5dea283c883e1d
    .dword 0xd29884eeb4eb18e6, 0x9faf031dc9261361
    .dword 0xaec3874c7960fa4d, 0x194ce07cca95dff6
    .dword 0x8bdd3731e4bfb34f, 0x12c8210570b1d99e
    .dword 0xa82a1b0f34d7d529, 0x73e89b98cbc7e52c
    .dword 0x79774380925a1078, 0xdaf9f1865c0c21a
    .dword 0x70bd34701afc38c0, 0x5fbad61a1b7fd05f
    .dword 0x11b60cb23d9eb34, 0x4dd12fb2849d75c5
    .dword 0x6e63b90c767580e5, 0x3a7fe87be56622c2
    .dword 0x2901529ef7e3bae9, 0x3ffc13618a569216
    .dword 0x5082e543d47f165, 0xe967b941dd6a447c
    .dword 0xd32c87ef0bc06a7, 0xe16ced58edbb2880
    .dword 0xf0e542e9164ee32b, 0xafb11e251ed00162
    .dword 0x551b5c4fdbb3f953, 0xc2cba438dbbcf8f9
    .dword 0xbf334797435c90c8, 0xabf887416115fd60
    .dword 0x85867235987d4d9b, 0x27b30e9e93122b46
    .dword 0xa9714ebe73377044, 0x8c5a3b3a97246993
    .dword 0xdc91bd248a78b8fa, 0x89e197b6c0b5478d
    .dword 0x1e951fc40fdabdad, 0xa0c06d26beb6301a

    .align 12
data7:
    .dword 0x5be2fe8d24677e5f, 0x5df272b076a06f60
    .dword 0x3c26eda4983c0c02, 0xdb2cbc24062dad76
    .dword 0xc1c31d1bf6e36246, 0x7eb10fa213b1c876
    .dword 0xead78d165e2bce5f, 0x8e37e2377b1b16c7
    .dword 0xce9a732964e294bf, 0x53fe0a355793462b
    .dword 0xeda43706bafcf366, 0xfd1349cd998c0721
    .dword 0x283d715aaf7c389d, 0x1903cf7eaa438f6c
    .dword 0x1e3009906a3a19b7, 0x5dd16615ba9f39c
    .dword 0xf55b42ce9d7a16a7, 0x355bea1f7959dd77
    .dword 0xe0ebe8a3e09e8270, 0x511864b3aaa5d26c
    .dword 0x1ff0074828c72dc7, 0x5ab40f23f0a611ee
    .dword 0x7b6c69bb572fc0dc, 0xfbbbb384d2495656
    .dword 0x8faa80e9fa5ce229, 0xa8906433740fe056
    .dword 0xf000c3c3832c9ff4, 0xd17e46a39fd98c1d
    .dword 0xc9818a43336655b2, 0xce0f8ed6bd55b91c
    .dword 0x55e38dac27d90766, 0xc71448337b5863f4
    .dword 0x31cd64c2af2d658, 0x14dc4c925138bec2
    .dword 0x6981be254b1b33f8, 0x34f119e9f29f8810
    .dword 0x5ab5c93f3d65e57b, 0xc361e01fdab124e0
    .dword 0x89164e63d06bd615, 0x739e0af516de88d1
    .dword 0x8c63c9e8e0ac4423, 0x7bf7c305ba1e47e
    .dword 0xa10db2091d3142ec, 0xcb76e20a6fec2cec
    .dword 0x8863da521f10cd91, 0xac8b8bc5cefe7682
    .dword 0xe0a8ed7d750c46a5, 0x985d97d726eb0de5
    .dword 0x47698d94e066099e, 0xc5f0ee21ab4802dc
    .dword 0xc72afe98eb0d3956, 0xaba48ae0b470e22
    .dword 0x5b9f49cdbff0f04, 0x94bf06dec1f5b5ba
    .dword 0xded4dca7d61bd30, 0xa796fc3d478d8c6e
    .dword 0x76305e8956c3ebca, 0xab4c72351255f6b7
    .dword 0x18a1a19860242e46, 0x520c76dac763f1a
    .dword 0xd39ee8e8c0be690c, 0x421622d7b7e3190e
    .dword 0x21e552e2cd9da280, 0xac26d321249a1cd7
    .dword 0x67da13982d524128, 0x917e8a280baa82ae
    .dword 0xc275c747a2263d0d, 0x9b24eccf99d81011
    .dword 0xac131f6f8255f354, 0xdfea1c2f40c650af
    .dword 0xd1bcda68476c26c9, 0xbbeaec407f3da020
    .dword 0xa62bb3bcdf751fd, 0xac23cb419ee1c69
    .dword 0x7e7b0bbf3885b4d5, 0x7a4bfbf3f0fa324e
    .dword 0x20004f2858f64a3b, 0x30568c87e1023f2d
    .dword 0x818c6f5e8722f018, 0x866ffbfbe59126d9
    .dword 0x83a30fa12d8f502a, 0xdccd744966c4a4ec
    .dword 0x89d768e615c0878, 0x199ca9c419aa12bd
    .dword 0xab5340780701062b, 0xc5a4989e6dec2db5
    .dword 0xae6f15eff2d331ae, 0xa595dfb7d2ab0ef3
    .dword 0x1ee600de85ccb83c, 0x65ed687bc1d2ebf
    .dword 0xbf3c99a0df842bc7, 0xe3a9ccaf5b8823df
    .dword 0x3abfddb9497511df, 0x2b5dbbdbb5c5022a
    .dword 0x5433d1f72f322b0c, 0x1e78ad06e2bc9c19
    .dword 0xf6db1809f3239ead, 0x683a22a639d8c9e7
    .dword 0xc14edabe847f4f9e, 0x37603a04b62737ae
    .dword 0x198dfc53aba0539a, 0xe2379b7de8da91f2
    .dword 0x22f995214da50439, 0xceae9bee12261e8e
    .dword 0xcfa60f129419c242, 0xce3cc2fcd80ce547
    .dword 0x5e852ccdb8cfdf5d, 0xb5dc736221b7ac58
    .dword 0x57542ccdb11a4d77, 0x2b1605e3108aa9a9
    .dword 0x3f77ec47767b2dba, 0x25db2ba868fe6263
    .dword 0x9f708e9ba33365f9, 0xa13be5b7878ed0a8
    .dword 0x6b361fda7c25ddc2, 0x7ed2317c6cea2f6a
    .dword 0xa8c1812a5d5bf3cf, 0x603877b621c74bf9
    .dword 0x96ed41519ac26f70, 0x7974752e279d8e30
    .dword 0x3e204afd7d47cc0f, 0x62e42ff006cf6828
    .dword 0x1a963fddb98cab66, 0xc4f00a1f193af4bb
    .dword 0xfbd03c347d373e81, 0xb9d350d0a0e37d51
    .dword 0x976cd9a0f0466f22, 0x9a6d4101314e4048


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
