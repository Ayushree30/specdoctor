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
pfx.bb0.l0:         andi x18, x18, 0x3f8                      
                    la x19, data5                             
                    add x18, x18, x19                         
                    fld f0, 8(x18)                            
pfx.bb0.l1:         andi x21, x21, 0x3f8                      
                    la x18, data5                             
                    add x21, x21, x18                         
                    fld f1, 16(x21)                           
pfx.bb0.l2:         andi x21, x21, 0x3f8                      
                    la x22, data6                             
                    add x21, x21, x22                         
                    fld f2, 16(x21)                           
pfx.bb0.l3:         andi x19, x19, 0x3f8                      
                    la x22, data1                             
                    add x19, x19, x22                         
                    fld f3, 0(x19)                            
pfx.bb0.l4:         andi x20, x20, 0x3f8                      
                    la x21, data5                             
                    add x20, x20, x21                         
                    fld f4, 0(x20)                            
pfx.bb0.l5:         andi x19, x19, 0x3f8                      
                    la x18, data2                             
                    add x19, x19, x18                         
                    fld f5, 0(x19)                            
pfx.bb0.l6:         andi x20, x20, 0x3f8                      
                    la x19, data1                             
                    add x20, x20, x19                         
                    fld f6, 16(x20)                           
pfx.bb0.l7:         andi x19, x19, 0x3f8                      
                    la x22, data2                             
                    add x19, x19, x22                         
                    fld f7, 8(x19)                            
pfx.bb0.l8:         andi x21, x21, 0x3f8                      
                    la x19, data1                             
                    add x21, x21, x19                         
                    fld f8, 16(x21)                           
pfx.bb0.l9:         andi x21, x21, 0x3f8                      
                    la x20, data7                             
                    add x21, x21, x20                         
                    fld f9, 8(x21)                            
pfx.bb0.l10:        addi x18, zero, 179                       
pfx.bb0.l11:        addi x19, zero, 39                        
pfx.bb0.l12:        addi x20, zero, 286                       
pfx.bb0.l13:        addi x21, zero, 290                       
pfx.bb0.l14:        addi x22, zero, 1718                      
pfx.bb0.l15:        addi x23, zero, 1476                      
pfx.bb0.l16:        addi x24, zero, 639                       
pfx.bb0.l17:        addi x25, zero, 1669                      
pfx.bb0.l18:        addi x26, zero, 719                       
pfx.bb0.l19:        addi x27, zero, 178                       
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
prp0.entry.l0:      call fn1                                  
prp0.entry.l1:      or x18, x19, x22                          
prp0.entry.l2:      flt.s x18, f2, f4                         
prp0.entry.l3:      call fn2                                  
prp0.entry.l4:      la x21, prp0.bb3                          
                    jalr x20, 0(x21)                          
prp0.entry.l5:      slliw x20, x18, 1                         
prp0.entry.l6:      bgeu x18, x20, prp0.bb3                   
prp0.entry.l7:      call fn3                                  
prp0.entry.l8:      fnmsub.s f3, f0, f1, f2, rup              
prp0.entry.l9:      jal x22, prp0.bb3                         
prp0.bb0:
prp0.bb0.l0:        fcvt.lu.s x19, f0                         
prp0.bb0.l1:        fcvt.d.wu f3, x18                         
prp0.bb0.l2:        beq x21, x19, prp0.bb2                    
prp0.bb0.l3:        sub x20, x19, x21                         
prp0.bb0.l4:        ori x22, x20, 1483                        
prp0.bb0.l5:        call fn2                                  
prp0.bb0.l6:        flt.s x20, f1, f3                         
prp0.bb0.l7:        fadd.s f1, f0, f2, rdn                    
prp0.bb0.l8:        call fn0                                  
prp0.bb0.l9:        fcvt.d.lu f1, x19                         
prp0.bb0.l10:       bne x18, x20, prp0.bb2                    
prp0.bb1:
prp0.bb1.l0:        or x22, x19, x20                          
prp0.bb1.l1:        add x20, x18, x19                         
prp0.bb1.l2:        sra x19, x20, x21                         
prp0.bb1.l3:        fmin.s f1, f0, f3                         
prp0.bb1.l4:        fcvt.lu.d x22, f2                         
prp0.bb1.l5:        fcvt.lu.d x19, f3                         
prp0.bb1.l6:        bgeu x22, x18, prp0.bb3                   
prp0.bb2:
prp0.bb2.l0:        fcvt.s.lu f2, x18                         
prp0.bb2.l1:        fmv.x.w x18, f3                           
prp0.bb2.l2:        bltu x21, x19, prp0.bb3                   
prp0.bb2.l3:        feq.d x22, f3, f2                         
prp0.bb2.l4:        sub x21, x20, x18                         
prp0.bb2.l5:        fadd.d f1, f2, f3, dyn                    
prp0.bb2.l6:        bge x18, x20, prp0.exit                   
prp0.bb3:
prp0.bb3.l0:        fclass.s x22, f4                          
prp0.bb3.l1:        divu x21, x20, x19                        
prp0.bb3.l2:        addiw x18, x22, 1057                      
prp0.bb3.l3:        fsgnjx.d f3, f1, f0                       
prp0.bb3.l4:        fcvt.s.wu f2, x21                         
prp0.bb3.l5:        flt.s x22, f0, f2                         
prp0.bb3.l6:        bne x19, x20, prp0.exit                   
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      fcvt.wu.s x20, f1                         
prp1.entry.l1:      fcvt.s.l f4, x21                          
prp1.entry.l2:      slli x22, x19, 1                          
prp1.entry.l3:      bne x21, x22, prp1.bb0                    
prp1.entry.l4:      call fn3                                  
prp1.entry.l5:      srai x18, x19, 1                          
prp1.entry.l6:      bltu x18, x19, prp1.bb0                   
prp1.bb0:
prp1.bb0.l0:        feq.d x20, f1, f4                         
prp1.bb0.l1:        xor x18, x19, x22                         
prp1.bb0.l2:        fcvt.d.wu f0, x18                         
prp1.bb0.l3:        or x20, x21, x22                          
prp1.bb0.l4:        fmsub.s f3, f1, f2, f4, rne               
prp1.bb0.l5:        call fn2                                  
prp1.bb0.l6:        fmadd.s f4, f2, f1, f3, rup               
prp1.bb0.l7:        call fn1                                  
prp1.bb0.l8:        bgeu x19, x22, prp1.bb1                   
prp1.bb1:
prp1.bb1.l0:        slli x20, x21, 34                         
prp1.bb1.l1:        call fn2                                  
prp1.bb1.l2:        bgeu x21, x18, prp1.bb4                   
prp1.bb1.l3:        call fn2                                  
prp1.bb1.l4:        fence.i                                   
prp1.bb1.l5:        call fn0                                  
prp1.bb1.l6:        mul x20, x19, x21                         
prp1.bb1.l7:        call fn4                                  
prp1.bb1.l8:        div x19, x22, x18                         
prp1.bb1.l9:        call fn0                                  
prp1.bb1.l10:       beq x20, x19, prp1.bb4                    
prp1.bb2:
prp1.bb2.l0:        mulw x20, x18, x19                        
prp1.bb2.l1:        beq x18, x19, prp1.bb3                    
prp1.bb2.l2:        fmadd.d f2, f1, f3, f0, rup               
prp1.bb2.l3:        fle.s x18, f1, f2                         
prp1.bb2.l4:        sub x21, x18, x19                         
prp1.bb2.l5:        sub x22, x20, x18                         
prp1.bb2.l6:        call fn0                                  
prp1.bb2.l7:        fcvt.w.s x22, f1                          
prp1.bb2.l8:        fcvt.s.w f4, x21                          
prp1.bb2.l9:        fcvt.l.d x21, f2                          
prp1.bb2.l10:       bltu x19, x22, prp1.bb3                   
prp1.bb3:
prp1.bb3.l0:        fle.d x19, f3, f4                         
prp1.bb3.l1:        fsub.s f0, f1, f3, rdn                    
prp1.bb3.l2:        fmax.d f0, f2, f1                         
prp1.bb3.l3:        fmv.w.x f0, x20                           
prp1.bb3.l4:        fadd.s f0, f1, f2, rup                    
prp1.bb3.l5:        fsqrt.s f3, f2, dyn                       
prp1.bb3.l6:        bne x21, x19, prp1.bb4                    
prp1.bb4:
prp1.bb4.l0:        xori x20, x22, 363                        
prp1.bb4.l1:        fsqrt.d f1, f3, rup                       
prp1.bb4.l2:        fmsub.s f4, f1, f0, f2, dyn               
prp1.bb4.l3:        rem x20, x21, x22                         
prp1.bb4.l4:        fclass.s x18, f2                          
prp1.bb4.l5:        fmsub.d f0, f2, f1, f4, rmm               
prp1.bb4.l6:        jal x19, prp1.exit                        
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        andi x19, x19, 0x3f8                      
                    la x21, data7                             
                    add x19, x19, x21                         
                    amoor.d x18, x20, (x19)                   
tc.entry.l1:        fnmsub.s f3, f4, f2, f0, rmm              
tc.entry.l2:        fcvt.s.w f1, x19                          
tc.entry.l3:        fle.d x22, f0, f2                         
tc.entry.l4:        or x22, x20, x21                          
tc.entry.l5:        bge x19, x18, tc.bb0                      
tc.bb0:
tc.bb0.l0:          sltu x21, x18, x22                        
tc.bb0.l1:          call fn3                                  
tc.bb0.l2:          divuw x21, x20, x19                       
tc.bb0.l3:          flt.s x20, f4, f2                         
tc.bb0.l4:          fcvt.s.w f3, x18                          
tc.bb0.l5:          blt x19, x21, tc.bb2                      
tc.bb1:
                    spdoc_check_c
tc.bb1.l0:          fmadd.d f2, f1, f4, f3, rdn               
tc.bb1.l1:          andi x21, x21, 0x3f8                      
                    la x18, data6                             
                    add x21, x21, x18                         
                    amoxor.w x22, x20, (x21)                  
tc.bb1.l2:          jal x21, tc.bb2                           
tc.bb1.l3:          sraiw x20, x22, 4                         
tc.bb1.l4:          call fn1                                  
tc.bb1.l5:          andi x21, x21, 0x3f8                      
                    la x20, data2                             
                    add x21, x21, x20                         
                    amomaxu.w x19, x18, (x21)                 
tc.bb1.l6:          fmsub.d f4, f1, f0, f3, rup               
tc.bb1.l7:          fcvt.s.d f3, f3                           
tc.bb1.l8:          call fn3                                  
tc.bb1.l9:          fle.s x22, f4, f2                         
tc.bb1.l10:         bne x20, x18, tc.bb2                      
tc.bb2:
transient:
transient_end:
tc.bb2.l0:          slti x21, x22, 1744                       
tc.bb2.l1:          andi x20, x20, 0x3f8                      
                    la x18, data2                             
                    add x20, x20, x18                         
                    sb x22, 24(x20)                           
tc.bb2.l2:          call fn4                                  
tc.bb2.l3:          andi x19, x19, 0x3f8                      
                    la x21, data2                             
                    add x19, x19, x21                         
                    lr.d x18, (x19)                           
tc.bb2.l4:          xori x20, x18, 313                        
tc.bb2.l5:          fence                                     
tc.bb2.l6:          fnmadd.s f4, f0, f3, f2, rne              
tc.bb2.l7:          andi x20, x20, 0x3f8                      
                    la x18, data7                             
                    add x20, x20, x18                         
                    flw f1, 20(x20)                           
tc.bb2.l8:          bge x22, x19, tc.exit                     
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
fn0.entry.l0:       sltiu x27, x24, 1695                      
fn0.entry.l1:       sltu x26, x25, x23                        
fn0.entry.l2:       remu x24, x26, x23                        
fn0.entry.l3:       fle.d x26, f9, f6                         
fn0.entry.l4:       fsgnjn.d f8, f5, f6                       
fn0.entry.l5:       feq.s x23, f9, f5                         
fn0.entry.l6:       auipc x23, 2840                           
fn0.entry.l7:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       fsub.d f9, f8, f6, rdn                    
fn1.entry.l1:       fcvt.s.lu f8, x23                         
fn1.entry.l2:       fmv.w.x f9, x26                           
fn1.entry.l3:       fcvt.d.l f7, x23                          
fn1.entry.l4:       fmin.d f9, f6, f5                         
fn1.entry.l5:       ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       fcvt.l.d x27, f6                          
fn2.entry.l1:       fmul.s f5, f6, f8, rup                    
fn2.entry.l2:       fcvt.wu.s x26, f7                         
fn2.entry.l3:       xor x23, x24, x27                         
fn2.entry.l4:       andi x26, x24, 1786                       
fn2.entry.l5:       sltiu x23, x27, 796                       
fn2.entry.l6:       slti x27, x24, 1474                       
fn2.entry.l7:       slli x23, x26, 19                         
fn2.entry.l8:       mul x27, x25, x23                         
fn2.entry.l9:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       fmv.w.x f9, x23                           
fn3.entry.l1:       or x23, x24, x25                          
fn3.entry.l2:       divu x23, x26, x24                        
fn3.entry.l3:       fmadd.d f8, f7, f6, f9, rdn               
fn3.entry.l4:       addiw x27, x23, 1258                      
fn3.entry.l5:       rem x24, x25, x23                         
fn3.entry.l6:       srliw x25, x23, 12                        
fn3.entry.l7:       fsub.s f7, f6, f8, rdn                    
fn3.entry.l8:       divuw x27, x24, x23                       
fn3.entry.l9:       divw x24, x25, x27                        
fn3.entry.l10:      ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       sra x25, x24, x27                         
fn4.entry.l1:       remw x27, x26, x25                        
fn4.entry.l2:       mulhsu x23, x27, x25                      
fn4.entry.l3:       auipc x25, 775                            
fn4.entry.l4:       addiw x26, x23, 659                       
fn4.entry.l5:       sub x25, x27, x24                         
fn4.entry.l6:       ret                                       
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
    .dword 0xda360f3304b52642, 0x938c3f0f7eced62d
    .dword 0xe4015f0021855ec7, 0x768787a0d4505222
    .dword 0x6d2317ffb07c3f8c, 0x4d42ec95149d2d7b
    .dword 0x67c40f3ba7848b8d, 0x3e53e18774d40a39
    .dword 0x9e8f2baf00d2fb4, 0x735b235d0aed22d6
    .dword 0x97d4c669dfc2c438, 0x4d3fe09fcb6efb56
    .dword 0x53ea2f7bac7b7232, 0xf718ae4d1afb4898
    .dword 0x753736ec2a72a3f, 0x9129860d57eec0de
    .dword 0xc0ac07ffb6e8913e, 0x62f67f1290f7d0cf
    .dword 0x905fe490d47e03e7, 0xaefe402004d3bc05
    .dword 0xc416ab21183e20fe, 0x1e02ce74d8014dd7
    .dword 0x70aaadea70e5088c, 0x7c00703d3f215879
    .dword 0xdc5117bd4bd09f65, 0x654db55c1caf63a6
    .dword 0xeb151fcfa3b9b441, 0x9cc2edf34077f362
    .dword 0x92534d2b6df518db, 0x237e7b44e168cb07
    .dword 0x4a9af43b913e16b8, 0x394256ccc5b8494e
    .dword 0x1afc7b896d561263, 0x212f7f703bf644a4
    .dword 0x6acd33ff87eec01f, 0xa527b98c8ca3e501
    .dword 0xd1741a48fd43aaf1, 0x210b75fe68866d7b
    .dword 0x787e9ad95a6c9297, 0xe1222fc170b90036
    .dword 0xf2b529224df0d28f, 0x56c6a94a9bf6b502
    .dword 0x3266fc331a24a6d6, 0x8d558e46f9eb3d94
    .dword 0xe89bcc8d5f47caae, 0xbf4d067769fd8d0f
    .dword 0x11b0d72cb4471cc8, 0x96bc9a24982be346
    .dword 0x32e9f37d4b2a6706, 0xcb44b11da955763
    .dword 0x5b7483e3e86d91f0, 0x71e018b72b7fc65a
    .dword 0x92188aba760d1901, 0x92cd62a52384a214
    .dword 0xaa3b77d4661086c6, 0x74db6f756d8caeca
    .dword 0x107d31c56585e3ee, 0xbfe5c55f5ad8303a
    .dword 0x38be63e1a9bb1fbc, 0xca67b2dcfa838803
    .dword 0xbab8705c0e963343, 0x5e6ef90624320e22
    .dword 0xc90d12b10d5e4015, 0x8e62c9a5d9c92e14
    .dword 0xc8087c256102b46, 0x577ba304a4961a11
    .dword 0xc27b1a6828d99a03, 0xc280f654dff30100
    .dword 0x1e132c2414056d2b, 0x7d025538bb5f4a33
    .dword 0xcfd017f3204352b6, 0x5accf4a679183ee9
    .dword 0x221d1d872028db9c, 0xe006e9b03d9fdf42
    .dword 0x9ee410d5a04f3922, 0x2e5fd809f13bfc14
    .dword 0xb847698f81d90796, 0xc667f8d007338cf0
    .dword 0xbe37c57094a8fd6f, 0x714dbc5ed3e890da
    .dword 0xee40cfba42bc683f, 0x4c3ee82a8b1dfde7
    .dword 0xf65f28fce8d222c4, 0xe065324e907a47b0
    .dword 0xf52835d64a2ef886, 0xd578dd09a685e51e
    .dword 0xa2b9e7b1ca09d4a7, 0x29dbcb9e0110d178
    .dword 0x9240ae1a483c2b3, 0x229989cc7f18ee5f
    .dword 0x239f3a9c0e697f65, 0xa3755e2678b287ea
    .dword 0xc6ff1b6b3d8dc199, 0xa9d1f0a244dba6fd
    .dword 0xf7b3cf927aa50166, 0xeb15e10759eb0ecb
    .dword 0x4feaa405b946de27, 0x132c7033799bc14d
    .dword 0xc396d9d659447401, 0x7f12d149e019e001
    .dword 0x4c851edb9fe8ac5b, 0x7cdba3ad40afbe83
    .dword 0xf57b1f4954b44da2, 0x7f00430d6ee46e5a
    .dword 0x3fb35e00e5917d1d, 0xbec67bbb19154b34
    .dword 0x237dc4ae76e9edbd, 0x340b29d7ec0dd8e4
    .dword 0x259da2c4b2ebc728, 0xa6b99249f0f95861
    .dword 0x591d287ad6f390fb, 0xf2e2e65c855a18a3
    .dword 0x6a64bfeaf24f039a, 0xf92c719407914d11
    .dword 0x7c9ef33b87c6264c, 0xd436936966d766bc
    .dword 0xc2b98ca2986ebf9a, 0xdcc39b9010b8e7f7
    .dword 0xb3a607983122d91a, 0xcf92c3898f5bda7d
    .dword 0x7289634ac847f9ab, 0xc73e4800d6c3cf05
    .dword 0x2b96c7816f0fdf06, 0x545a4fd719b67add
    .dword 0x62a3d6b70df50589, 0x1ab31b4d097e1128
    .dword 0xada1f68122aabb4c, 0xaa736d737b0a1f32

    .align 12
data1:
    .dword 0x24dc471cf4c38224, 0x6d60f5b74ae6b444
    .dword 0xeb970541502d8899, 0xe51c260ba3896c21
    .dword 0x796b3084d4519649, 0x8fa51c7ead8098f9
    .dword 0x2d4bd9260e548e3a, 0xc994889ec4a7b6c1
    .dword 0xe38998cd517aa8df, 0xfe3d8d0cd39ad162
    .dword 0xab20f924b157d697, 0x70d1dc4e33ee698a
    .dword 0x51de04092d56c241, 0xfa39e2a842ec976f
    .dword 0x699e534b187ffb5c, 0xf63ee90962a4f88e
    .dword 0xb35f2290b5b051ec, 0x77c48328cb71417b
    .dword 0x4e97c023ff671706, 0x89c19a60070b1e4b
    .dword 0xed6f102c3b5d3255, 0xdf2d2e389622fa00
    .dword 0xe331fcf095c448c3, 0xff01fe4b34fbaa13
    .dword 0xfc68537992e6dd9e, 0xfdb26c3c512ec5b
    .dword 0xcb3db061f62642b3, 0x4dd0b14a26e89744
    .dword 0x83ff1e8023d55879, 0x3a7c7698bc65dbf2
    .dword 0x940459eade785c5c, 0x9e362cc54c924c92
    .dword 0x430f25e2f591e7f, 0xbc4485c0527c5bf5
    .dword 0x7d914c3f45156e9, 0x82ebd7faafce9c5c
    .dword 0x1da1107aca089049, 0x3dae0e460095c54d
    .dword 0x8e4b8999758b5267, 0xcc36b6b7b2c48ec1
    .dword 0xfab75654dbd22f9a, 0x443583a9b9b8d20d
    .dword 0x477cdf539325f72b, 0x73c68d92645db58b
    .dword 0xa519db152536ac32, 0xd80c0d1de6650e49
    .dword 0x5d7b5fe1bd73839, 0x9e7d08ef50471aa8
    .dword 0x6fa2edf45c8e454, 0x2c9e16f7e685f155
    .dword 0x4afb2b9fd0b297ca, 0x1100c7c6a9226dc7
    .dword 0x1f3bec911c9df2ef, 0x6c9371eeba0ef42f
    .dword 0xfecb62e811599237, 0xa4d263c57bf0322
    .dword 0x7e41d1ec876575d3, 0x5377869f5d32f68d
    .dword 0x640430640ba1ed81, 0x8149de1bc2dcf5be
    .dword 0xbedbe9dfe22ee07, 0x9a315e0b32b99bb9
    .dword 0xb2ef0a8fa6b004f4, 0x90d032a528a19ded
    .dword 0xa69c9a182bd3d034, 0x3063e8deca37a365
    .dword 0xdceae2b51d1dec4c, 0xdb2213cb69849ce3
    .dword 0xd0f18e5230430771, 0x22b7bd07cd7387f5
    .dword 0xbfa4b7f3a2c5725a, 0x602257909e17f4e6
    .dword 0x7d139c7d8dac28ef, 0x59f4989e7b588e3c
    .dword 0x1291417c28413515, 0xdcb21082a57aebd6
    .dword 0x299706a114b1abc6, 0xf6730bcf4ebab5c1
    .dword 0xfa00fc6300a4682b, 0x6fc10dba83d3c7f1
    .dword 0x7be35955e6755d72, 0xb416ebb7b91bdcd
    .dword 0x671864ac82699abf, 0x1a3a664805999b94
    .dword 0xa01cb80eba457970, 0xe32b60e6a2daa836
    .dword 0x2d58441731038456, 0xa0cc5eb1fa8da9f9
    .dword 0x240e403cef405e83, 0xff6be8e96443bbf1
    .dword 0xa4abfa6e2a8020bd, 0x392235c69597375d
    .dword 0x80bf7ac69552d7e5, 0x2dad294e32131814
    .dword 0x62bbf5c295bacdb7, 0xfc9d55b648f25028
    .dword 0xf60903c8eb9665e9, 0x142dcd14f247ac7e
    .dword 0x6e1bc645601f85c2, 0x310ea12eb22a532a
    .dword 0xe4ea280ce0e89758, 0x74c3d243cf46adda
    .dword 0x19520aae70ffaaf9, 0x586dc855237b72d8
    .dword 0x1017ad662c83ad3a, 0x9e864572945d5e69
    .dword 0x1a30030d41782f95, 0x4b9880efd485404d
    .dword 0xbda6fac6985af3d4, 0xa99fb89b0325f002
    .dword 0xcdc1b47c477ee3f0, 0x8d4040f57353c9df
    .dword 0xab57a556d1921739, 0x3229cf3c528f7de2
    .dword 0xefe28933d2307015, 0x3a9abcb36d26f10a
    .dword 0xfad2a80a49dc351b, 0x9ed1c581a939f122
    .dword 0xd8792e0f58f50e72, 0x7fe717c53a584f44
    .dword 0x32ac9d40f7c1d8bf, 0xa859c08d071b5f4c
    .dword 0xfa9a2246b0a38d03, 0x7ffa29aa208b1516
    .dword 0xf1714767e7239770, 0x316c8bea4fd0be7a
    .dword 0x679d19cb197cfbd6, 0x76396bc3f3917a1c

    .align 12
data2:
    .dword 0x735f166c6b9888c9, 0x74c85b31af700b75
    .dword 0xcb1ad504b439c762, 0x4f70a24a454ffbbd
    .dword 0x8f6aafae13264295, 0x115f8c7f625c20a3
    .dword 0x467464401e334c3c, 0x9e74d767920cf6c0
    .dword 0x1384dfcb40062c5b, 0xe9a09b1b141b6109
    .dword 0x9dc3b3f2a651471d, 0x4659036ee2f52706
    .dword 0x24422e88bc8febb8, 0xfdb36db38d5106b2
    .dword 0xef213d5cd117ce40, 0x32bc13aa7f95e2c4
    .dword 0xe25db91fcd37342d, 0x478dc0c43606f57b
    .dword 0x339ed8039e5cb730, 0x847b0b5bca6b2a4c
    .dword 0x2061357594c630cd, 0xbd234da03399ff52
    .dword 0xb04f0638301d74f1, 0xe434a62851fe3ac4
    .dword 0x64e2783b2be5e570, 0x1ec51dad4dc4a87f
    .dword 0x9581dd6e7db9f96b, 0xce9fa330ece3d0ab
    .dword 0x68096f7b7f5f7b85, 0xaadf2973e276bf4d
    .dword 0x9b015e197bb30e1b, 0xb2a0f5701c463169
    .dword 0xe5d936d22eb8bc14, 0xa4e4df575b3ab105
    .dword 0x258767c13c49a54, 0xd2b7490300ad8e35
    .dword 0xb2c540ccace24e4e, 0x309068420a20c03d
    .dword 0xa2f28c91623bda1b, 0x9b4202966afdd842
    .dword 0x54fa9bb7c9e717e, 0x402d8149a209b40
    .dword 0x5867f755606fbb5c, 0x71d4e5a1a01f7905
    .dword 0x920abaed11b3d583, 0xa8d1fce70170d0b4
    .dword 0x5cbcfc98a68d2efe, 0xca977ec9712f72b0
    .dword 0x233efaa7172044a6, 0xa90edb043db9c3ef
    .dword 0xf09aaa11af80a387, 0x277f6b326537e505
    .dword 0x9efa03fe1691f87d, 0x5df3408f3695e7a1
    .dword 0x246cf39fcd67bdf9, 0xc1d75f8028557998
    .dword 0x1dab3bc5273a4d51, 0x4b99477a5d5121cc
    .dword 0x1ff3c6adb1a42893, 0x97f01b9e5adffbc
    .dword 0x9c47ee90ad71946b, 0xb3d172695a428ce5
    .dword 0x6d146853aca8f9ac, 0x22f8817a2f84159
    .dword 0x364295b5367d335d, 0x468825fc40c1f7fc
    .dword 0xa3325c1e6ec16758, 0x86701de35029ae90
    .dword 0x30c4e088efadf34a, 0xc4e4f6ea0ee2dd98
    .dword 0x421f6db68a2444fb, 0xc8296a4832dbb434
    .dword 0x2a05b7daf68f7496, 0xb81a09522bc22ce2
    .dword 0xd40fb45877df6582, 0xba4652fe9e39fee5
    .dword 0xa4bd3b12ab431ce5, 0xe6bcff0eca19791b
    .dword 0x3e1fe3156082c113, 0xc2c7839657bdcc32
    .dword 0x285343e27d08fc09, 0x4aaf666e6c89d7c0
    .dword 0x6474006e797c5bd9, 0x3aadfd4c3578b437
    .dword 0xb72afce02080b99d, 0x344cbfd823553144
    .dword 0xfe7d17a817fb7634, 0xf4d94a7bf2f22dcb
    .dword 0x3836d2a61740a88e, 0x8eac26f073a00bf4
    .dword 0xdf948a0b82be5af4, 0x538f544346036463
    .dword 0x4e974dc7a09353c1, 0xa351e318ddf62aa1
    .dword 0xc5ac1304d6b75f1d, 0xa69ff7642fc84cb6
    .dword 0xc9f640fbf3731d23, 0xab2da7e08099b86b
    .dword 0x17e7c48c08ad6637, 0xc376af337ad8a62c
    .dword 0x7de149088cb179d8, 0xc8675b90e7df0436
    .dword 0xbf86e0e6e95599d5, 0x3042c4dc0562559e
    .dword 0x54f17eacfc967f, 0x256c12a34d9b4f3b
    .dword 0x26b9a19eb4142fa8, 0xa6d63ded45c553d3
    .dword 0x560a5b1defcb2086, 0x3e96c8022f099362
    .dword 0x623f7fccc755d77b, 0x360478e2db14fdb8
    .dword 0xb0df34321bec7082, 0x5cde9440d46eade7
    .dword 0x88c080fbadb6e2d9, 0x51bb8baa71f2165c
    .dword 0x9f9d5db1a8cf48cb, 0x5a11a0d378a3489d
    .dword 0x92bb96df87af91be, 0x45f0aed8295d744
    .dword 0xdd6df52ba3120842, 0xc7a3f2b2b6c8560f
    .dword 0xec9b4edaf93d076, 0xb45e60a2e09cb5d2
    .dword 0xc18016f4b24fae9, 0x47ec14fd86a7a60d
    .dword 0x5707afd11d3a6318, 0xa5e0ac48c856cbee

    .align 12
data3:
    .dword 0x692374c9616df15d, 0xe7f7d912575ef45d
    .dword 0xe55ed0b8ebe33eb6, 0x49171d04a2c3fffa
    .dword 0x7316b0b48a20f02, 0xc4c40961b9bf3ad5
    .dword 0xe5d2f5580b1f2c15, 0x29672a238539a3b0
    .dword 0x37f7364302e7becd, 0x2dad54fd75d8d7f1
    .dword 0x3323e72af5d420d7, 0xee286258d6730acc
    .dword 0xd87642137ca17bbb, 0xe2aed6e28e69f5ad
    .dword 0x90764c9f66cc127c, 0xc95855aee7b854cc
    .dword 0xaa919ece796faba2, 0xc3b197277d396e2b
    .dword 0x6f662c9d8ce8e19, 0x2c0edf67ee72a6e3
    .dword 0xff8224f6b8b8bb91, 0xce81b98270dea1ff
    .dword 0x99ffaa382fa46b47, 0x3a013297e508a6
    .dword 0xa0fd22980334fe57, 0xd454fe6c3770ee4d
    .dword 0x216bd8bff5b6d1e7, 0x44e7f2758d9bbac
    .dword 0x2e8055b469024ddc, 0x409c6eb9baba50c6
    .dword 0x53c4911e317427f8, 0x79f685b5a7568d
    .dword 0x6768319d05fffc2d, 0xabd6b75576f43ca7
    .dword 0x404e343bdbc690d8, 0xbefc83ccb9350045
    .dword 0x9762503c6fa78a76, 0xf7bfd6a77540a2b7
    .dword 0x25822944c2065397, 0x31fefa393e7d77e6
    .dword 0x3af41017d7ef4394, 0xb46833f509f6488a
    .dword 0x69c242098fff88ce, 0x36839b1c3169199c
    .dword 0xc3278eb2a45f6c76, 0x7e1343a68a9e0532
    .dword 0x17cd552dd101fc55, 0x6569526cff7e70a9
    .dword 0x389f21f63c597038, 0x1db35e3ea4d70246
    .dword 0xf68e2c9b074784c9, 0xe55b706e68528657
    .dword 0xbdb08a6bf794924b, 0xa0ce14265a996356
    .dword 0xdb4aa73412a53348, 0x25595b2502c5dd66
    .dword 0xc124052c61479945, 0xed9ed3e59c5546b
    .dword 0xed474f67afdf967b, 0xcb0a3af2070a5c7e
    .dword 0x107c403fc69061b6, 0xa6a9b056f6d0cb21
    .dword 0x7a423c06f7fd3b6, 0xa73125348a873bb
    .dword 0x9b3602b60a365c03, 0x634e31db8de17ede
    .dword 0x6af4def3936b29d4, 0x1d7eafb242e56eb8
    .dword 0xf472e3c8a277e106, 0xfbf4958f0da97054
    .dword 0xa656c9c91231391a, 0x25cb1c199adf25e8
    .dword 0xd6d925d3a2e2c165, 0xcb0971a8827afa55
    .dword 0xc587f71799f7bd13, 0x987e7c64d796e9b2
    .dword 0x19b263cc45e61710, 0x9f96aedaa04a46cb
    .dword 0x475a00480d6c64d7, 0x419df440523e979a
    .dword 0x4f8299e01fc36209, 0xb245643ac074459f
    .dword 0x9811c9490ee4a9c6, 0xbb02527dd220e27a
    .dword 0xb403c377c93c5805, 0x3ffd78da20791e89
    .dword 0xfb4f92d30c7dc87c, 0xd26f49695c78b2bd
    .dword 0x18389ad98cc04d52, 0x186f703397e75357
    .dword 0x4de570734dc9b74e, 0x39dc41506d21f2a5
    .dword 0x3c3de1599973fea5, 0xca4bbb4cb1438e0e
    .dword 0x5874babe86c7f8a7, 0x781c08457b6b82ff
    .dword 0x8d8d1e42009dfc25, 0x5530741a8ec7f753
    .dword 0x428f65621f9df5c7, 0x1ef202b9f2f9cfcf
    .dword 0xdd65b51c5a8e6f1d, 0x5a3e315b202c2b48
    .dword 0xfcf43d5b358969d6, 0x78a6e02bb888a867
    .dword 0x7ec5384068828f39, 0xa853d165ddb753ec
    .dword 0xe9196aa3e0bd2062, 0xf051a1ed78ae4d3a
    .dword 0x28825cbb1bd01df, 0x96b1ec951f2239f1
    .dword 0x4a082d991ba9a0d3, 0x7a814f9625005fec
    .dword 0x19b20e8649c126f8, 0x31b8ac35603ddef1
    .dword 0x749201737d2e2da, 0x4862aade31d90b07
    .dword 0xee068c18064219a, 0x897881946d243fee
    .dword 0x5bda2f0a9457171c, 0xd8a2422b011b8f73
    .dword 0x8181631c42fa034e, 0x1e43c7fb2689fd71
    .dword 0x9fa5cf00993da9dc, 0x62f6af500a72e975
    .dword 0x819c6cd02016dde9, 0x9896b3143df1c2d9
    .dword 0xf40bad1cc21c98b6, 0x18ddb4e3343f3889

    .align 12
data4:
    .dword 0x2c729b4d6033a6ba, 0x26bde70b35006d33
    .dword 0x26c686b6b95e6926, 0x8fff19af76440e4
    .dword 0x1150edb15ca1d8e9, 0xc546c3bb2f66ffdf
    .dword 0x8b0d9e46dad2a3f1, 0x5c63e436d94134c8
    .dword 0xb7970d365fef382a, 0xcbae7e1fef3c14bf
    .dword 0x9bb1a7830d5dc85b, 0xdaf5e64115d94a78
    .dword 0x7f172902e8004fe8, 0x52912cb6798b9625
    .dword 0xc226b4cafdafcb63, 0x3e66d632acf377aa
    .dword 0xc4b2c1fbecab2ffb, 0x3f24d97265cdbe2e
    .dword 0x5167e029f46919d9, 0xae52e685ad6c87ad
    .dword 0xf398c8bb2496838f, 0x65de210777708392
    .dword 0x53db8e6ebd41d86c, 0x94960be1c1756933
    .dword 0xf3a4ced6c69c26cd, 0xebe3f04e3c288231
    .dword 0x85b355bf050bf160, 0xe00356a161b17f69
    .dword 0x110c77db600a03fc, 0xe74ecde044a344ba
    .dword 0x8ab9137887a432bc, 0x9adcb50ec8d3ea33
    .dword 0x2cb79993b05e9def, 0xcec6468f79f9f6d1
    .dword 0xd976e484b6c98d18, 0x68f17566acd1f2eb
    .dword 0xf794b14d7f564302, 0xa31c6916d1027d7a
    .dword 0x1374442c65457d70, 0x6a49357159a463e9
    .dword 0xb10ca00f403bf0c7, 0x65ee6c26cc657de0
    .dword 0xf29e083794c23841, 0x6d5074e7f88a0640
    .dword 0xecee19ffbe4d50cf, 0x41fb31156480bd2
    .dword 0x740e9ebeb26d779e, 0x262684d8ef885a6c
    .dword 0xf64a574e98397a78, 0x3fe10589fc38bce9
    .dword 0x2a53552a84a66f01, 0x18216dd5eb48ae69
    .dword 0x2887eb7bb9406ea7, 0x2e623e8fa817a245
    .dword 0xfc42e19df62815ad, 0xa2d229362430712
    .dword 0x9041bff96618297, 0x4e4a877fd2717f6b
    .dword 0x77d151a14ab387db, 0x254a078208045fd
    .dword 0xb9e035d1398e33b5, 0x9d956e6d0ff50e9b
    .dword 0xbb95ce5d14d1ce7f, 0x5cd5849bdc35676e
    .dword 0x5df0d4ecb0f145d7, 0x9316d1c40c1181f6
    .dword 0x824eee026a8c53dc, 0x8151c06243dd9c1b
    .dword 0xfb1a975b353b1196, 0xffb0fb8e01271ac2
    .dword 0x46341521e1316f98, 0x988ac9febc9f45c8
    .dword 0x77712d8ccfbdfe8c, 0x3b0a43d950762b4e
    .dword 0x4a670f0b855b611, 0x9b24e31f73631db1
    .dword 0x223c715ba23273dc, 0x17b11e266dc1f217
    .dword 0xbbb586bbe119a7bb, 0x8d5b9b8ff7947f91
    .dword 0xccd958074f66a8a, 0x5aba6d7280f20623
    .dword 0x9b3de0428428f8da, 0xdf39b1ee98931a47
    .dword 0x4ef288c86b5de486, 0x8b7856ae7a9867cd
    .dword 0x1eb93ed037ca6479, 0xcaeca75893f14d7a
    .dword 0x8ace659a0f272df7, 0xbbf6cabf3e2e81a3
    .dword 0xcf46a593cd922b6c, 0x86f98705913f10bc
    .dword 0x39ab44306bf30228, 0xf76f42f0eea7fef
    .dword 0x9afb5cb853a31cb0, 0xfacf585235e6d958
    .dword 0x1b1056e123c48c0c, 0x3ac8dfff42e06765
    .dword 0xaef0b73d1c922822, 0x4b99b7db1847856b
    .dword 0x6dbe38936d230226, 0x5059eea4c6f255ae
    .dword 0x6e880837a9b6aa81, 0x919cdabf7535a547
    .dword 0x8a498b7fb8df8a16, 0xfad96cb0d1c15066
    .dword 0x8e83e1ac9f3bd068, 0x3552912d10633e03
    .dword 0x1ff2dfd2b9f93af9, 0xa234f2e40191a5f3
    .dword 0xcabce5f8957e651, 0xb1338d8641712c7d
    .dword 0xcb54dc618bc91b78, 0xcf8f279004c66444
    .dword 0xaa11433ac7e0f664, 0xe96397509bb1c24f
    .dword 0xb85fa84c331f26dd, 0x1c5e8a8d6e921307
    .dword 0xfb6f491ea3897b5d, 0x4833d16c28f31789
    .dword 0xd08f76ac28b0d7ef, 0x4392e1c4cb436e7a
    .dword 0xe4599013d50894c, 0x986fd6c9476ca848
    .dword 0xd76aec4af1b380c6, 0x42fc9e4d103e6544
    .dword 0xba8a17be8576d7b6, 0xc1453a2f2da3f495

    .align 12
data5:
    .dword 0xfbe64cfc96b0ab1, 0x9166c5458e5abe3d
    .dword 0x9f4e0ad4d4ce5c48, 0x9693c0a323b748e
    .dword 0xe340386e8325f869, 0xec97376db507792e
    .dword 0xd933b98810e9a92d, 0x6b10a393fcb03847
    .dword 0xcbdce01952d566da, 0xcd431d1b06587c57
    .dword 0x2812541da1656438, 0xbe5925f06d2e913b
    .dword 0x8759b431ee9fa690, 0xc4366cc563cdf6c1
    .dword 0xe45f6ce3d2e71db4, 0x3a083dd91b8c9c33
    .dword 0x1bd287b9d79fb864, 0xb85fb379f8801df0
    .dword 0x580c1d2e8392c75e, 0x3177bfc73e18847e
    .dword 0x7aa1ef9445418d07, 0x72e1c2b18d76b04a
    .dword 0x3ea008d4a58cd013, 0xdebb05bdd6eede02
    .dword 0x7e1ab654ef75283b, 0xa5c45ba9b3fe54bd
    .dword 0xa4d176761d5f8018, 0x89a240f86a1eb123
    .dword 0x88421be68287f2e2, 0x12b09ab24db1a3b3
    .dword 0xed4ed1cf5f1b2445, 0xab3a50507675fe54
    .dword 0xa34a7a789ef72311, 0xff53f96d7697c2a1
    .dword 0xbb2f6bfa909aa014, 0xd2eda0887073f5d6
    .dword 0x2416ad51f2be1af4, 0x9641d53c8493d43e
    .dword 0x512ad2389e5c49fa, 0x909bbb9bccc022fe
    .dword 0xe57508c6069133b5, 0x67c94eeb211ab24f
    .dword 0x622379d7c87ffc88, 0xd5585093f954ba58
    .dword 0xeded4d1f53463499, 0x3d33e75145fba0b6
    .dword 0x93777c2c9a068db2, 0x750ea9ea2c03dd2d
    .dword 0xd6144fe84a8314d2, 0x455cddf25fb3b512
    .dword 0x9622a47a6de43d03, 0xde5c4a96cc7c2f52
    .dword 0x3c87c67b211c416d, 0x9baf972cf960259d
    .dword 0xbe80af2edfcf5a7e, 0x1060b72e985b8384
    .dword 0xaaaa3dbe51ae76a9, 0xfd8ea7c05be6baca
    .dword 0xfcfc81f7c43c89fa, 0xb8ab4b9c1affe6
    .dword 0x10db6d42dab64bfc, 0xd77ea3f73ce52132
    .dword 0x1e62cea1a1f7b158, 0x7e261bc8745f2da5
    .dword 0x7a1bf9738bf8c8c0, 0xd157e3f5e91b8286
    .dword 0x24579416c165c679, 0xa0c490d101f9fe0b
    .dword 0x652054c5963a5603, 0xca13ab79a3ee2113
    .dword 0xb07ee9911d6d5826, 0xd3969ccc99ea5d2e
    .dword 0x57f230b3bb4794fb, 0xa3f5b56959c7db94
    .dword 0x250f24d22db7e3f3, 0x121a0fda73fa0d06
    .dword 0x41092329c017547b, 0x2e79d02e5b471b54
    .dword 0xb933c5ccfc1c6c, 0x7c0f92f981b84577
    .dword 0x3beda61bc9ea7a91, 0x311a00e095182ba7
    .dword 0x3210f949cad82c07, 0x34ba231d4ebd5f6c
    .dword 0xb5b582fef6e805b4, 0x85cf99928f520005
    .dword 0x481f638652a78a31, 0x38ff8feaed907fd0
    .dword 0x5d54b47d9eba36ac, 0xf73aed99e6f1b561
    .dword 0x89049367218fc2ca, 0xc4f26edc7d56aab4
    .dword 0x5a5deb163bcd4edc, 0x6c67ae6c4b99da99
    .dword 0xef30963a93090fd7, 0xb3a106810978dbb4
    .dword 0x85a9ad936520441f, 0x6311c9be98b38ec8
    .dword 0x5e74689b794f189b, 0xb1c5b183c5c04c65
    .dword 0x8024014549950101, 0x1e549da80eb41c44
    .dword 0xde9603d64fb87b26, 0x65461b75c2fb1940
    .dword 0x218bf1e6b1f06983, 0x729bc72702e55c31
    .dword 0xaa59d6af14b89c5b, 0xdd676e86e5a15010
    .dword 0xae0cc56a3f6fdaec, 0x5dad90473718d213
    .dword 0x1489952517752bde, 0x97dbc2fa5922843
    .dword 0xc259ef85c5b1c848, 0x2441025048f2e4f0
    .dword 0x5fd723855fab4252, 0x9d1e78439958a093
    .dword 0x6c2264abfe45339, 0x7cae37aaadfc7c5a
    .dword 0x3c8f40293dea5acf, 0xddbba4a50e1fc1e0
    .dword 0xd4e38b64b15db1e6, 0xa97d1bc4fb848e68
    .dword 0x696a33d9753e95c6, 0xebbacf2e9d4b335f
    .dword 0x35eaad010c8f5391, 0x4a53cb8b5cb1526e
    .dword 0x3febca3dcfe2e0d2, 0x18750c567a86ce26

    .align 12
data6:
    .dword 0xe0002d6172be47df, 0x317b58f6492c3676
    .dword 0xd2f81b0933aac2f6, 0x5f42a0b3ff92a847
    .dword 0xcdcdf84159114338, 0x3d5c2f47a7251831
    .dword 0xe1bd3d4af9ab544a, 0xdbd3b7df4e520f4b
    .dword 0x18ffba180690d13c, 0xa418758ca935fcec
    .dword 0x32c3ccf3a977bb2e, 0xb109c572e2dff626
    .dword 0xa0c34b989cc1e610, 0xc0fd96e992bfcd94
    .dword 0xe803b3804a9eeedf, 0xf2ac5b8e8fdd54e0
    .dword 0xebbdc1d51418e671, 0xc89ea29ee327608b
    .dword 0xfb87e752e71b7849, 0x64cb3e667bc8cf90
    .dword 0xfd5eb4a157fcc142, 0x30aa415c00fd512b
    .dword 0x7d37fe67b24cbfe7, 0x941be9d013604b10
    .dword 0x898753b638717ee8, 0x773433c13813f0f
    .dword 0xf6a0424ede559df5, 0xa695b5417b36e5c2
    .dword 0x4089fd16501a852f, 0xdda7b0ba506490d7
    .dword 0x3c54759c1f2ce5e, 0xbfab1069f12ac635
    .dword 0x5471e7216f24b0d2, 0xc39bf3ad6770287f
    .dword 0x13ad0ddd2a80f1a, 0x17bf8b29d7991160
    .dword 0x85d42dbe8979b0ff, 0xc5db5afae8668e5
    .dword 0x1757935dbe8d7e8f, 0x3acd55937d67acd8
    .dword 0x8a7495d8968a357, 0x1fee3670661352b
    .dword 0x1a24cd075383a4da, 0x238131b125d2db2
    .dword 0x743565f080071525, 0xa5c4e475043885c6
    .dword 0xbfd2d4927e378fd, 0x6ab5096f53d29040
    .dword 0x3b16c888cc695c73, 0xd6643cc868142868
    .dword 0x64713b7d1bc89f4f, 0xc3527dc9d7f0ba6
    .dword 0xd94f36ec32e25d51, 0x6f91730a3f2b66d4
    .dword 0xb2274e97320ab5b1, 0xb6f5801e48d6df2a
    .dword 0xf41da709d9f49537, 0x842e060284d8516f
    .dword 0x4e7cf8ea3e9918a4, 0x7e7fc59f8cb33baa
    .dword 0xbddedd8a5d93d8d7, 0xa22cc0bb07b81f83
    .dword 0xf33b4bde3020a82d, 0x73ed36f2f40a6918
    .dword 0x43cc70e1dcd5c089, 0x6d9e5f700e6cf8b0
    .dword 0x73205a1f30bfa426, 0xd4364ef3d375adeb
    .dword 0x2b392ab6acbd9ef6, 0x2a9fc433bd9ef972
    .dword 0xc6914e02bd723b1a, 0xf2ab896eed6ac77d
    .dword 0x6fee5ab6381bc88d, 0x9d49fd99284fac56
    .dword 0x5c6e97852f07b058, 0x5e99b2045c293723
    .dword 0x1e941d233ce8e39, 0x4e0f8f6b322f3733
    .dword 0x93eb6d9c24699bed, 0xfe0b939c6811f9b8
    .dword 0x422680fe397768a8, 0x9a2bf3c522c66092
    .dword 0x787dfe57d41e4d0, 0xbd859a3525cf441e
    .dword 0x421f14dddbf81594, 0x188fb306aedf2818
    .dword 0x650e00dde7027aa2, 0x6270402ea099eea0
    .dword 0xd40d2dccc2983074, 0x50b9b8e1a52ce9
    .dword 0x8d5d4d05a7d37080, 0xd55d52006f8e8afd
    .dword 0x76c832ec5a93450d, 0xde2371c2b540d916
    .dword 0x1d1182641cd33714, 0x3fca1fb08d02fa3e
    .dword 0x5324af91a6ce1c68, 0x21992f04f665e886
    .dword 0xebee2e9307b532b7, 0x9365f52451914793
    .dword 0x534d446aaec6200f, 0x50dc5d954ec34390
    .dword 0x320a0a48a962b4b1, 0x1245110adf4566fd
    .dword 0x6ee216883d73b36d, 0x57c10a33bddc6c80
    .dword 0xbf051a48ebc20527, 0x492323af582fe3ab
    .dword 0xc87bf1a8530b972a, 0xf5476e763b6d8628
    .dword 0xdc5be7288f697c71, 0x21dd504ee935f2e8
    .dword 0x78730e459eb84577, 0xcd78f0f4a972754
    .dword 0x8a9c3d632ade8290, 0xd4ce28d3e4ba1df8
    .dword 0x26b4b7068ef49cf7, 0x7da389d062f92bed
    .dword 0xbb270a107cb372b0, 0x9e449819183f3e2d
    .dword 0xc43061d691e1f4b9, 0x494b3e14ab668dff
    .dword 0xdfcd906c4f174d5c, 0x75feed6a74a203e0
    .dword 0xd3efe6b2f126c26d, 0xe7fbc2f612ae0c9a
    .dword 0x59b6a85ca93fed05, 0xcce90df1bb05b32b

    .align 12
data7:
    .dword 0xf88c0f82b9c73f7f, 0x1e3e71cc89f3c8b0
    .dword 0xd1b0cdd5de405282, 0x754779e9a2fdffd2
    .dword 0xb20fc0f33d6a5ce9, 0xe149487c6a63eeb5
    .dword 0x89e3414f1a9e1edf, 0xd91254752cb41e27
    .dword 0xce8879ac14c613f5, 0x4844614c2fd5b5d9
    .dword 0x3f0560a14578a704, 0x78faeba7ce7c7b12
    .dword 0xccdb09c97d266086, 0x121a575cd7ee5de2
    .dword 0xdf112038d3c37d5e, 0x70f3954c07528366
    .dword 0xd0fe0cc1a83ecfb6, 0x5a7a886984b1f438
    .dword 0x1523dc28a145b31d, 0x56b0adc7d747ec3f
    .dword 0xb76b334e9b8af18f, 0x4ff9b302f50206e5
    .dword 0xb8c4e0ca03f1126, 0xa96893e9f2a49b76
    .dword 0x812269d56ea7eb35, 0x6e3543fe8cd56616
    .dword 0xfe14e08ae7f76897, 0xa47a19a62506c39d
    .dword 0x37ea586e70df479e, 0x672a5f238dfe2024
    .dword 0x7df76a9d4ef8f2a2, 0x202dd1e58dcabae1
    .dword 0x361e37735c5d1443, 0x62333686aaa5c380
    .dword 0xd536dadc02d154d5, 0x98bb3a814903dae9
    .dword 0xf1c8f725acab81d4, 0x8a20e08d9d66d174
    .dword 0x6cb0d046df35c655, 0x36b8a7d5da783c20
    .dword 0x85b865fa19f80461, 0x2f28d067e9db4e98
    .dword 0x1a6ba1aa6e948c89, 0xfefb215eaa353e34
    .dword 0x9e73478c85aaf4a5, 0x408fd98108dfebd5
    .dword 0xe72c697a9e2e7f4f, 0x705dbf221a619405
    .dword 0x3bbdd344f4c3e2c, 0x84edf52959580bdb
    .dword 0x7b5868d61e4bb151, 0xfb7c7acb5e18f7d1
    .dword 0xee95ce393aeff309, 0xfad17f18b30ffd12
    .dword 0x7c76e4b2a4847beb, 0x23c387c90c8282bd
    .dword 0xbdb98a6ce38328c0, 0x5f4c8ca1b957ad75
    .dword 0x6ac601881aa88e93, 0x8476522b1457c71
    .dword 0x640146b3f67d61df, 0x457e4be25c67f2f
    .dword 0x91e4fead79d29448, 0x62f9a13b6835535f
    .dword 0xbebda0233da01ce3, 0xb0ad117c2d07d971
    .dword 0x4d771c9d4175241d, 0x22a5cc4b2c3fdc91
    .dword 0xab6fe7b269df1963, 0x5ac67bf20c882741
    .dword 0x6991497f2c2da1f3, 0x362f5b33a1f6e24b
    .dword 0xc100e2802457325f, 0xfa634da1af5c1ee2
    .dword 0xddd6f31565250a6f, 0xd1e7bb3cef4f3143
    .dword 0x41cae624db8f22a2, 0x16a3d4cb59351532
    .dword 0xd7d82517a64ce829, 0xe23248b32aa31986
    .dword 0xc56e84ec3ffaf59b, 0xec3b471a99163a41
    .dword 0x1be7ee1fe07a5859, 0x526526acaf9123ed
    .dword 0x8ed17cb768a57d49, 0xebdd12262debdc3c
    .dword 0xb214c6dea7d1a469, 0x526588b288f95b4d
    .dword 0xb259842a7b68fc16, 0x673af5a87db6f7d8
    .dword 0x212db080caa7607f, 0x29b9ddde212085ee
    .dword 0x5b1c3a1535eb40f3, 0x44a347b23d1d353e
    .dword 0x104ce3220585e779, 0xb758ed916b406df4
    .dword 0x1f60458d65d117dd, 0xc066aadf0eb0b472
    .dword 0x52add6b6542b8cf7, 0xa05afb08ad48580f
    .dword 0x674bbbb6a249d88e, 0xae7f08dd8630bbb4
    .dword 0x7847fa31cafd698b, 0x6d2aa14ed9219a52
    .dword 0x7b383654fb322803, 0xa25617e4a7befe2b
    .dword 0x6406f16ddcba26fe, 0x8e9b6f57c631f9f8
    .dword 0x675348372f408a57, 0xb312b8477b89c812
    .dword 0x54274229b3a58e80, 0x91be8df8a7b8af68
    .dword 0x108c21de14385c0, 0x8218d77bd59dbbba
    .dword 0x4abe098e06f87a4d, 0x83fcfe8e3e9f570d
    .dword 0x36611779802c4843, 0xd725c5715365cc08
    .dword 0xdff06259ee32542c, 0x88a9f639b9c27089
    .dword 0x7f5d2a68b5024d39, 0xec61d51a490bd286
    .dword 0xd53be879b90a440e, 0x57521548bdb8d677
    .dword 0x1164413a9a700b20, 0x8d48c84695253422
    .dword 0x61fb4424b331ee0d, 0x8e24e821ad4c011c


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
