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
                    la x21, data3                             
                    add x19, x19, x21                         
                    fld f0, 0(x19)                            
pfx.bb0.l1:         andi x22, x22, 0x3f8                      
                    la x21, data3                             
                    add x22, x22, x21                         
                    fld f1, 16(x22)                           
pfx.bb0.l2:         andi x19, x19, 0x3f8                      
                    la x21, data3                             
                    add x19, x19, x21                         
                    fld f2, 24(x19)                           
pfx.bb0.l3:         andi x22, x22, 0x3f8                      
                    la x18, data6                             
                    add x22, x22, x18                         
                    fld f3, 16(x22)                           
pfx.bb0.l4:         andi x22, x22, 0x3f8                      
                    la x21, data2                             
                    add x22, x22, x21                         
                    fld f4, 0(x22)                            
pfx.bb0.l5:         andi x19, x19, 0x3f8                      
                    la x22, data1                             
                    add x19, x19, x22                         
                    fld f5, 8(x19)                            
pfx.bb0.l6:         andi x20, x20, 0x3f8                      
                    la x18, data5                             
                    add x20, x20, x18                         
                    fld f6, 8(x20)                            
pfx.bb0.l7:         andi x20, x20, 0x3f8                      
                    la x22, data2                             
                    add x20, x20, x22                         
                    fld f7, 0(x20)                            
pfx.bb0.l8:         andi x21, x21, 0x3f8                      
                    la x20, data5                             
                    add x21, x21, x20                         
                    fld f8, 0(x21)                            
pfx.bb0.l9:         andi x20, x20, 0x3f8                      
                    la x19, data0                             
                    add x20, x20, x19                         
                    fld f9, 0(x20)                            
pfx.bb0.l10:        addi x18, zero, 1295                      
pfx.bb0.l11:        addi x19, zero, 1867                      
pfx.bb0.l12:        addi x20, zero, 250                       
pfx.bb0.l13:        addi x21, zero, 804                       
pfx.bb0.l14:        addi x22, zero, 482                       
pfx.bb0.l15:        addi x23, zero, 1186                      
pfx.bb0.l16:        addi x24, zero, 1000                      
pfx.bb0.l17:        addi x25, zero, 1373                      
pfx.bb0.l18:        addi x26, zero, 755                       
pfx.bb0.l19:        addi x27, zero, 71                        
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
prp0.entry.l0:      fclass.d x21, f4                          
prp0.entry.l1:      fsgnjn.d f1, f3, f2                       
prp0.entry.l2:      fcvt.d.lu f4, x21                         
prp0.entry.l3:      fclass.s x18, f4                          
prp0.entry.l4:      srliw x20, x19, 14                        
prp0.entry.l5:      divw x21, x20, x19                        
prp0.entry.l6:      fnmadd.d f2, f0, f3, f4, rdn              
prp0.entry.l7:      fcvt.s.w f1, x21                          
prp0.entry.l8:      add x21, x19, x18                         
prp0.entry.l9:      fcvt.s.l f2, x20                          
prp0.entry.l10:     bltu x20, x22, prp0.bb0                   
prp0.bb0:
prp0.bb0.l0:        jal x20, prp0.bb3                         
prp0.bb0.l1:        bltu x20, x19, prp0.bb3                   
prp0.bb0.l2:        call fn3                                  
prp0.bb0.l3:        fcvt.d.l f2, x19                          
prp0.bb0.l4:        bltu x20, x22, prp0.bb3                   
prp0.bb0.l5:        fadd.s f2, f4, f0, rdn                    
prp0.bb0.l6:        blt x18, x19, prp0.bb3                    
prp0.bb0.l7:        fsqrt.s f2, f0, rup                       
prp0.bb0.l8:        call fn2                                  
prp0.bb0.l9:        fcvt.l.s x21, f0                          
prp0.bb0.l10:       jal x21, prp0.bb1                         
prp0.bb1:
prp0.bb1.l0:        fmv.w.x f1, x18                           
prp0.bb1.l1:        fcvt.s.w f2, x20                          
prp0.bb1.l2:        call fn0                                  
prp0.bb1.l3:        sltiu x19, x22, 838                       
prp0.bb1.l4:        fmul.s f4, f1, f3, dyn                    
prp0.bb1.l5:        fnmadd.s f1, f3, f0, f2, rtz              
prp0.bb1.l6:        bne x21, x22, prp0.bb2                    
prp0.bb2:
prp0.bb2.l0:        bge x18, x22, prp0.exit                   
prp0.bb2.l1:        call fn1                                  
prp0.bb2.l2:        srl x21, x18, x19                         
prp0.bb2.l3:        fmv.x.d x19, f1                           
prp0.bb2.l4:        fsgnj.s f3, f2, f0                        
prp0.bb2.l5:        slliw x19, x18, 7                         
prp0.bb2.l6:        sraiw x18, x21, 1                         
prp0.bb2.l7:        call fn4                                  
prp0.bb2.l8:        bltu x20, x18, prp0.bb3                   
prp0.bb3:
prp0.bb3.l0:        fence                                     
prp0.bb3.l1:        feq.d x19, f0, f2                         
prp0.bb3.l2:        fcvt.w.d x21, f2                          
prp0.bb3.l3:        fcvt.wu.s x20, f2                         
prp0.bb3.l4:        divw x21, x18, x22                        
prp0.bb3.l5:        sra x18, x21, x19                         
prp0.bb3.l6:        call fn1                                  
prp0.bb3.l7:        fmax.d f4, f0, f2                         
prp0.bb3.l8:        fcvt.d.wu f0, x18                         
prp0.bb3.l9:        bne x20, x19, prp0.exit                   
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      fcvt.d.lu f1, x18                         
prp1.entry.l1:      fcvt.wu.d x20, f3                         
prp1.entry.l2:      call fn2                                  
prp1.entry.l3:      fmadd.s f0, f4, f2, f1, rne               
prp1.entry.l4:      call fn2                                  
prp1.entry.l5:      la x22, prp1.bb0                          
                    jalr x20, 0(x22)                          
prp1.bb0:
prp1.bb0.l0:        call fn4                                  
prp1.bb0.l1:        fcvt.d.s f2, f2                           
prp1.bb0.l2:        blt x19, x21, prp1.bb1                    
prp1.bb0.l3:        call fn2                                  
prp1.bb0.l4:        fcvt.d.lu f2, x20                         
prp1.bb0.l5:        fcvt.wu.d x21, f2                         
prp1.bb0.l6:        bne x22, x20, prp1.bb3                    
prp1.bb0.l7:        fsqrt.s f4, f3, rtz                       
prp1.bb0.l8:        call fn1                                  
prp1.bb0.l9:        la x20, prp1.bb3                          
                    jalr x18, 0(x20)                          
prp1.bb1:
prp1.bb1.l0:        fcvt.wu.d x19, f1                         
prp1.bb1.l1:        fcvt.w.d x18, f4                          
prp1.bb1.l2:        call fn4                                  
prp1.bb1.l3:        fcvt.lu.d x21, f4                         
prp1.bb1.l4:        fnmadd.s f0, f3, f4, f1, dyn              
prp1.bb1.l5:        fsub.d f1, f0, f3, rtz                    
prp1.bb1.l6:        fsub.s f0, f3, f1, rdn                    
prp1.bb1.l7:        sraiw x21, x20, 10                        
prp1.bb1.l8:        sltiu x20, x18, 76                        
prp1.bb1.l9:        fcvt.wu.d x19, f1                         
prp1.bb1.l10:       beq x20, x19, prp1.bb2                    
prp1.bb2:
prp1.bb2.l0:        fsgnj.s f4, f1, f3                        
prp1.bb2.l1:        fcvt.d.l f0, x21                          
prp1.bb2.l2:        mulw x22, x19, x21                        
prp1.bb2.l3:        fcvt.w.d x22, f4                          
prp1.bb2.l4:        fmin.d f3, f2, f1                         
prp1.bb2.l5:        fsqrt.d f1, f0, rdn                       
prp1.bb2.l6:        fcvt.l.d x21, f0                          
prp1.bb2.l7:        fadd.s f2, f0, f4, rne                    
prp1.bb2.l8:        call fn0                                  
prp1.bb2.l9:        call fn4                                  
prp1.bb2.l10:       jal x18, prp1.bb3                         
prp1.bb3:
prp1.bb3.l0:        bgeu x21, x22, prp1.exit                  
prp1.bb3.l1:        fmsub.d f4, f2, f3, f1, rne               
prp1.bb3.l2:        divu x22, x21, x20                        
prp1.bb3.l3:        fcvt.s.d f1, f1                           
prp1.bb3.l4:        call fn3                                  
prp1.bb3.l5:        fcvt.wu.s x20, f0                         
prp1.bb3.l6:        bgeu x19, x18, prp1.exit                  
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        fmul.s f4, f2, f0, rup                    
tc.entry.l1:        andi x18, x18, 0x3f8                      
                    la x21, data2                             
                    add x18, x18, x21                         
                    amoxor.w x20, x19, (x18)                  
tc.entry.l2:        fmsub.s f3, f4, f1, f0, rmm               
tc.entry.l3:        la x21, tc.bb0                            
                    jalr x19, 0(x21)                          
tc.entry.l4:        and x18, x19, x22                         
tc.entry.l5:        blt x18, x20, tc.bb0                      
tc.bb0:
tc.bb0.l0:          rem x19, x21, x18                         
tc.bb0.l1:          fadd.d f2, f1, f4, rne                    
tc.bb0.l2:          fmv.d.x f1, x21                           
tc.bb0.l3:          mul x22, x19, x21                         
tc.bb0.l4:          fadd.s f3, f0, f4, dyn                    
tc.bb0.l5:          auipc x21, 3148                           
tc.bb0.l6:          blt x22, x21, tc.bb1                      
tc.bb1:
tc.bb1.l0:          call fn1                                  
tc.bb1.l1:          andi x20, x20, 0x3f8                      
                    la x22, data3                             
                    add x20, x20, x22                         
                    sh x18, 20(x20)                           
tc.bb1.l2:          call fn0                                  
tc.bb1.l3:          fence.i                                   
tc.bb1.l4:          fnmsub.d f2, f3, f0, f4, dyn              
tc.bb1.l5:          srl x22, x21, x19                         
tc.bb1.l6:          fsgnjx.s f4, f0, f2                       
tc.bb1.l7:          fclass.d x21, f2                          
tc.bb1.l8:          la x18, tc.bb2                            
                    jalr x20, 0(x18)                          
tc.bb2:
tc.bb2.l0:          fcvt.wu.s x19, f0                         
tc.bb2.l1:          sltiu x20, x21, 1948                      
tc.bb2.l2:          andi x18, x18, 0x3f8                      
                    la x20, data1                             
                    add x18, x18, x20                         
                    amomin.w x19, x22, (x18)                  
tc.bb2.l3:          bgeu x18, x21, tc.bb3                     
tc.bb2.l4:          fcvt.wu.s x19, f3                         
tc.bb2.l5:          andi x19, x19, 0x3f8                      
                    la x18, data5                             
                    add x19, x19, x18                         
                    fsd f3, 8(x19)                            
tc.bb2.l6:          andi x21, x21, 0x3f8                      
                    la x20, data4                             
                    add x21, x21, x20                         
                    lr.w x22, (x21)                           
tc.bb2.l7:          la x18, tc.bb3                            
                    jalr x21, 0(x18)                          
tc.bb3:
tc.bb3.l0:          divw x22, x20, x19                        
tc.bb3.l1:          andi x21, x21, 0x3f8                      
                    la x18, data1                             
                    add x21, x21, x18                         
                    lr.d x20, (x21)                           
tc.bb3.l2:          andi x18, x18, 0x3f8                      
                    la x19, data2                             
                    add x18, x18, x19                         
                    amomaxu.d x20, x21, (x18)                 
tc.bb3.l3:          fnmsub.s f1, f2, f3, f4, dyn              
tc.bb3.l4:          blt x21, x22, tc.exit                     
tc.bb3.l5:          beq x22, x21, tc.exit                     
tc.bb4:
tc.bb4.l0:          sub x21, x19, x22                         
tc.bb4.l1:          fcvt.w.d x19, f4                          
tc.bb4.l2:          mulw x22, x21, x20                        
tc.bb4.l3:          andi x20, x20, 0x3f8                      
                    la x18, data0                             
                    add x20, x20, x18                         
                    sh x19, 28(x20)                           
tc.bb4.l4:          andi x22, x22, 0x3f8                      
                    la x21, data2                             
                    add x22, x22, x21                         
                    fsw f3, 4(x22)                            
tc.bb4.l5:          fcvt.wu.d x19, f1                         
tc.bb4.l6:          jal x21, tc.exit                          
tc.bb4.l7:          andi x20, x20, 0x3f8                      
                    la x18, data5                             
                    add x20, x20, x18                         
                    lb x19, 4(x20)                            
tc.bb4.l8:          slliw x20, x22, 12                        
tc.bb4.l9:          la x22, tc.exit                           
                    jalr x18, 0(x22)                          
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
fn0.entry.l0:       sltiu x23, x25, 220                       
fn0.entry.l1:       flt.s x25, f8, f7                         
fn0.entry.l2:       flt.s x26, f6, f7                         
fn0.entry.l3:       fsgnjn.s f8, f5, f6                       
fn0.entry.l4:       fcvt.wu.d x25, f6                         
fn0.entry.l5:       divuw x25, x23, x24                       
fn0.entry.l6:       fmv.x.w x23, f7                           
fn0.entry.l7:       fcvt.d.w f5, x25                          
fn0.entry.l8:       xor x23, x27, x25                         
fn0.entry.l9:       ret                                       
fn0.exit:
fn1:
.align 8
fn1.entry:
fn1.entry.l0:       fcvt.d.wu f8, x25                         
fn1.entry.l1:       slliw x27, x24, 27                        
fn1.entry.l2:       fdiv.s f7, f6, f9, rne                    
fn1.entry.l3:       fmin.s f7, f9, f5                         
fn1.entry.l4:       fcvt.lu.d x25, f6                         
fn1.entry.l5:       ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       srl x25, x26, x24                         
fn2.entry.l1:       fcvt.wu.d x27, f5                         
fn2.entry.l2:       fdiv.d f5, f6, f7, rdn                    
fn2.entry.l3:       fcvt.w.s x25, f9                          
fn2.entry.l4:       flt.s x25, f7, f5                         
fn2.entry.l5:       fsgnjn.d f7, f9, f6                       
fn2.entry.l6:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       fence.i                                   
fn3.entry.l1:       fence.i                                   
fn3.entry.l2:       andi x23, x26, 2                          
fn3.entry.l3:       fmv.d.x f8, x23                           
fn3.entry.l4:       and x23, x24, x26                         
fn3.entry.l5:       fdiv.d f9, f8, f7, rup                    
fn3.entry.l6:       fle.s x25, f9, f7                         
fn3.entry.l7:       ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       remw x23, x25, x26                        
fn4.entry.l1:       xor x25, x24, x26                         
fn4.entry.l2:       fcvt.lu.s x23, f9                         
fn4.entry.l3:       fence                                     
fn4.entry.l4:       divw x23, x25, x24                        
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
    .dword 0x75bcc47d16eb3618, 0x4f73c0f0f56826db
    .dword 0x96f6f9f73c327c62, 0x7a43f2812b9f93ec
    .dword 0x674256a2fdfe381c, 0x4672539de56ccb04
    .dword 0x9b4bc5b5b7402147, 0x482f78c290873e36
    .dword 0xeef702a0a9ae0228, 0x650a99aff68526c8
    .dword 0x39a331e5f5f705ad, 0x1caae575fb2c44c8
    .dword 0x25a8dfc7d4065e44, 0xdeaeb8afafa5432e
    .dword 0x30fa5cfa6053fc40, 0x828fdb62a5ebad1f
    .dword 0x1014cddff4b3539d, 0x45538dbba0239e23
    .dword 0x82266f8089a45e17, 0x8c1b6d852c516d18
    .dword 0x4930f08e150b9604, 0x90f6b79503447180
    .dword 0x1cba6f4cb5b63b8a, 0x199b03a36d8c76c4
    .dword 0x7661330251140262, 0xc78b6628fe494678
    .dword 0x4687316a04a98af7, 0xbb17e1db28d29e63
    .dword 0x1acfce732ee572b, 0xe5b8faf92bcbdf31
    .dword 0x828a986301c06b9b, 0x29d4d3500afefbed
    .dword 0x73f13e0341a724e8, 0x149f1454511e549b
    .dword 0x434ddffe91d2c4e2, 0xd837ad9edaba504c
    .dword 0x8cdde9d343073038, 0x903c3e31c4e286f4
    .dword 0xbdf1e59d16fac7de, 0x54af851e92d62b6d
    .dword 0x6fd5f20ceb1ff584, 0xd6ceb208025b4f38
    .dword 0x50436bc401fa55b1, 0x49d12122c3a6566
    .dword 0x7b8c0e96f84fdc44, 0xbaf57c5ecc0352a1
    .dword 0x956f9215e7ac56c0, 0xbad58b616bb5c546
    .dword 0xaeef77b5f5d3f0fb, 0x363594e5aa97e846
    .dword 0x579f0a37a5102a75, 0xee130120995c825f
    .dword 0x6769312bee178376, 0xa294176d6ea7ad7b
    .dword 0x40816966c1842a53, 0x2c5c68450edae840
    .dword 0xeeb8ca290143ea6, 0x4874b0dfc6aa478
    .dword 0x8cdd78d8271a52f6, 0x38525bb2eddc80eb
    .dword 0x379efed83690cc77, 0xd83d2c5e5c517881
    .dword 0x5222c6251b17fa0f, 0x284b4f61a0291ca6
    .dword 0x71b28433d62e268f, 0x7721db8e6382bfa6
    .dword 0xfe3978fb8f1ba6c1, 0x9fe529dfd2242e52
    .dword 0xa60478acf5e1620d, 0x24f412b150aa7d5d
    .dword 0x5c746312fe538f12, 0x7565c0c63110d1fb
    .dword 0xf1567e1e567dfbc1, 0x13ae66478aaf3365
    .dword 0xb2837213922c3232, 0xd3b668e7c3c5b6f7
    .dword 0xb5043ed015a978f4, 0x4cfbfc3313b56b9f
    .dword 0x8e3fe62ea69c3fba, 0x88688ec1cae2e6c4
    .dword 0x9c46fe5768a9c977, 0x2372d39dc1c639ea
    .dword 0x4d35542510a77556, 0xcd7c57de2fb841e8
    .dword 0xcf6e0aff79fb38d1, 0xc1b66dd7cf5f5be6
    .dword 0x5aa1a0f8c9182a68, 0x1e7d22d6fd02f444
    .dword 0xadce90243273ced2, 0x5ab3476d8f26aef1
    .dword 0xb469f5996b9949af, 0x9069d88f22347e84
    .dword 0x2411ef5ab5ea6bfa, 0xdd534e3a466aea74
    .dword 0x1698d8f45a9426d7, 0x9fa561108ff7bd65
    .dword 0xec8228a50471f9cb, 0x9645e0ab99ef9ca8
    .dword 0x4c53a01273b17bb3, 0xf0a2fa292bbb981c
    .dword 0xc62a2c4fd099b163, 0xf4fae670cf3d19e7
    .dword 0xbb296d4f9c4b0424, 0xc8cdb457e5751552
    .dword 0x1a229af80c759c60, 0x1681f116d425b1a7
    .dword 0xaadb4030e41d16ea, 0x40b8a1490d2deecb
    .dword 0x86857b57e9487d3e, 0xb33f04e1edaf4f49
    .dword 0x2a7836f3074d1b1f, 0x50f968a792a329b4
    .dword 0xd17c92c45c67c508, 0x650ebacf71391b4e
    .dword 0x340ad348da007c27, 0xcb5e58d5edd445de
    .dword 0x822eca8ebcbff7cf, 0x90cd3871daa57e6e
    .dword 0xccf4d6178d8b9832, 0xcd514a7737263e28
    .dword 0xd591fe1cd6acda5f, 0xfcfb50e3e2fa7569
    .dword 0xa56f89d0c470c4a8, 0x3c4c342e4b281176
    .dword 0x76d194dfb6585d83, 0xa44f7febd71d7dde
    .dword 0x701e5b7659ad77b5, 0x5fa0f33b00ccab41

    .align 12
data1:
    .dword 0xf02c9f84efc0bb2a, 0x722be0a63d7c4d50
    .dword 0x5b0b7e821e1e1a46, 0xc9f0e1d69ee47adf
    .dword 0xc8e701eba9ef61e7, 0x33302c1a96783c21
    .dword 0x90b86b8e433c5271, 0xfe52e045c420df18
    .dword 0x618ae4910020443b, 0xcbc83dee90277522
    .dword 0x375e73747673e011, 0xf9d07c2e1fc92bf4
    .dword 0xcfd1523891cda507, 0x4bd9b8d9e2a7d8d0
    .dword 0x123672d70079f254, 0xa047a17af569d202
    .dword 0xe68f06a5dd93e6e2, 0xbb01e347b64eccbd
    .dword 0x1812f422a034f453, 0xdca7ed22e6413f8
    .dword 0x48a8c86250db73f3, 0x5058e35546aeb5fb
    .dword 0xe7050bfceda62dc8, 0x77249196c3d039e8
    .dword 0xe70ec13469a9f81b, 0xe93b02443ba5555c
    .dword 0xb413748cb01ed20, 0xcb0056f77bccfcc9
    .dword 0x8c7e736374f95085, 0x38a572dd53e84a03
    .dword 0xf5261aaeaead4e6e, 0x9287bdd979421ca3
    .dword 0xe334f1f75c746c05, 0x2fabd4a9eeabcc6b
    .dword 0x86d33a0a60d4c19f, 0x348e17daf06b5e6d
    .dword 0x8b74e4a3b5e3096f, 0xcfc88a3984801bdc
    .dword 0x61bf1dd559fe00cb, 0xbc3c6630cfef51b6
    .dword 0x8ded0749a5a1a4c9, 0x9a6629089cc7bde4
    .dword 0x1e28400cce6bc69, 0x7d2a61d9e184ef98
    .dword 0x91c1dd067d03ce68, 0x12a533d23bec9d46
    .dword 0xecbcc9c280f5e286, 0x150d85e0f60ed028
    .dword 0xeed4155a071658fc, 0xa4af4f1e8b53e196
    .dword 0x85d68e16acc2171b, 0x452d92920bd567aa
    .dword 0x57688ac72aa3457c, 0x3d91e651b29a27bd
    .dword 0xd0c6ae2ad680408b, 0x37e8f1052e544ee9
    .dword 0x78442374e01b4b31, 0x3b41babd2adaa9fe
    .dword 0xa58b1d54b021ee0b, 0xa6371e8e28b4fbbe
    .dword 0xea7c9f1a33c0899f, 0xf5634c8936f1db03
    .dword 0x21bf37b92762b4f, 0xd37ba065bca47f48
    .dword 0xc6151d923d90e6c4, 0xbfcc337cb0b9f0e4
    .dword 0xc48a0518c497856d, 0x739d5c09ee7828ad
    .dword 0x4f59ce1e6203ef2f, 0x9c911756238b3ed1
    .dword 0xffb00f0f4fb12eed, 0x9e7413438d6c818a
    .dword 0x308fe74c5f68957e, 0xddb9c7c11de663d1
    .dword 0x1b7fac8f724574f3, 0xd57f37194a027c3b
    .dword 0x9e61b57e8924098a, 0xf97187114106f4c6
    .dword 0x3f76af2abe257a11, 0xd0d2d69a37cb9d87
    .dword 0x2790b94afc4bad84, 0x1db510c475c0e405
    .dword 0x787f49b498f55a72, 0xd0f58e622d992d3c
    .dword 0xcc3f6014ffffb58a, 0x782b084e3224b362
    .dword 0x35fad5c7306e5e60, 0xe54613b04497665c
    .dword 0x9710db65ebdaa85, 0x76ed9bcbb3d1bf47
    .dword 0x734b84c0fede2d88, 0x28e523988632aa8f
    .dword 0x77b616cb6d372ea4, 0xbec8db7bd8a5854e
    .dword 0x7c8462f36b21a09d, 0xbd16ea2cc8f30da4
    .dword 0x913d0ba7bbe5227a, 0x860f9ffa39124d1e
    .dword 0x3d70d95fe0934ac1, 0x9b19b4ece2875646
    .dword 0x89099d998ec420f4, 0xa2ec0347a9ed1a79
    .dword 0x44b113c1ba73778d, 0x167bbb42ad6832cc
    .dword 0x1ed984ad607850d3, 0xcb94910286e8604c
    .dword 0x8f1a5eadb36df350, 0xfc7a97f85e5c3297
    .dword 0xcc7083f092b9d4fd, 0xb58f6b9ff0a68277
    .dword 0x134d5dc515501b0d, 0x8d35855ca2d0b59b
    .dword 0x89e42e421cead11, 0x332879951e706d42
    .dword 0x4072fa31146fa5db, 0xf88205f686cc477b
    .dword 0xf612399882620ade, 0x929be7b508cb8f50
    .dword 0xbddfad9fbac64b10, 0x8ca0610309cc9a73
    .dword 0xeee580cd6d1fe091, 0x9fb3186bd98f642d
    .dword 0xa5ab7b70148b94b8, 0xf2d2af47e007783b
    .dword 0x918d6f87c6f17f5f, 0x446ba2e590c9cdb0
    .dword 0xc254a64bc10e953d, 0xb014be7176a10bdf

    .align 12
data2:
    .dword 0x384f83f9fd7832be, 0x26825b3e0df6ef6d
    .dword 0xb048a3c9bf8c7baf, 0x94b4ffe0768bb8e0
    .dword 0xd09f2976847367c8, 0xb9972f98f487d469
    .dword 0x5aab23ff9f24ace4, 0x71b0a3c2ad6fd6f6
    .dword 0x21dab12d949cf906, 0x35b763409dd616ce
    .dword 0x366c92d6b371866a, 0x7f0e280d1707f1ce
    .dword 0x7ad69659aae449d5, 0xaa6aa23a4372fb35
    .dword 0x1fb123bb06eee86f, 0x871599fd6fad1f2a
    .dword 0x704758786dfd1876, 0x6293cd25a8ec4f1a
    .dword 0xfad9eac69fbf9252, 0x78921dc47d0c311b
    .dword 0x5008dfb2469ce7e, 0x952780dc637ef87d
    .dword 0x5adafa2045720b13, 0x3ecbd13d9561a4f7
    .dword 0xc23d9e6c21b6de50, 0x11f3a2d8d0ecdd60
    .dword 0x3e29163ffddf170d, 0x98d89127341772af
    .dword 0xedd69fd7f8a08ea0, 0xf1ab5adca5a58953
    .dword 0x1c920ec7c24cb86e, 0x933746f64f904418
    .dword 0xc9dc30595cac90e0, 0xeedea0723e1bac64
    .dword 0x8f1207059b4ddb19, 0x3f0cd6b5bb1e250b
    .dword 0x8c37e1e19bf248c5, 0x508c0f63100c2d7f
    .dword 0x40a678118fa467a5, 0x5fd23bdbea95ac11
    .dword 0xdae767df0fe58dec, 0x40904e33d432aab6
    .dword 0x82d83d54e0deef86, 0x7d5e32ecd50aa47d
    .dword 0xa3229e3a353e1bb3, 0xe4081dc9bbcc8cd7
    .dword 0x7eb68a54ebd3578, 0x75b9fe28331b1060
    .dword 0x550ce1f95b64d56f, 0xee238f20841f5332
    .dword 0x97be73d890a35771, 0xf5d3d35e0f2d5efb
    .dword 0xfe8e48c108a07e68, 0x610d999603fac0c8
    .dword 0x1628030c65377976, 0x969d98c7062c29e8
    .dword 0x3dcff01ce5748b24, 0x3886cd76b2eb306b
    .dword 0x68787444376eb68c, 0xa26e7ab4f4bc6122
    .dword 0x8a8d6b9bf14f7045, 0x8b059f090229bcb1
    .dword 0x493c460bca285368, 0x24b891978fdfcf3a
    .dword 0x1a58aa40e49def2f, 0xbde3598d16e320e1
    .dword 0xb00b98d704c04e3b, 0x1ea91f1b11868526
    .dword 0x4ea1811fd551df43, 0x23b60396f84b8a18
    .dword 0xa99e446a4b5479ba, 0xc23ed8b1baebfc81
    .dword 0x37956f5a4c8d174b, 0x7661175e2d0e2c4b
    .dword 0x7b10d7719ad0ef01, 0x7badee3245e2adce
    .dword 0xa68d75645198288d, 0xbd5b72914d4e6905
    .dword 0x67eb2563f3ad46dd, 0x46d9a1232f5f8ae4
    .dword 0x7485a02bf9979fc, 0xae281bcc41510633
    .dword 0xe15dd41bcb275c7f, 0xff8f7ef61f613683
    .dword 0x106baa68a9538ef0, 0x1a6af6be31132796
    .dword 0x74424b9f4483989, 0x79ed0399e886bf40
    .dword 0x8150cc9203da6494, 0xed472040d4ce361
    .dword 0x6a49ffda80d5196a, 0xd2ceeefa7421a5ff
    .dword 0xa5149a72f08652b1, 0x584407d6742b6122
    .dword 0x449fa0d5e5914f15, 0x2ddf7b85a4040559
    .dword 0xeaf4c2e2cd13e354, 0xb17cb8717b6334b6
    .dword 0x636de1063fa772f9, 0x56b1bdcf9015d348
    .dword 0xa88db244cc9d818f, 0x26ef487181266d33
    .dword 0x6054cc5b6af8c5e7, 0xfe3697669a84c533
    .dword 0x28ec3c178c94cfc9, 0xc6858306b308fd35
    .dword 0xf1280fba0467d7ed, 0x12d4597d1bbaba35
    .dword 0xb314998efe231c, 0xb442de218de4fad9
    .dword 0x9254305a08b44e7b, 0xd1faa5c914dbd5bb
    .dword 0x4240d708c4ac0eaa, 0xd4d8fe595574b0f5
    .dword 0xead6caaa6e8347e1, 0x1b2e6836e1518a2b
    .dword 0xf5a9c6d212f04264, 0xb819dc9f654e6c69
    .dword 0x24ed83207a591179, 0xd158e044d1957da5
    .dword 0xb6db9e77b9840145, 0xff76641690b67dbf
    .dword 0xc082427a910d34c4, 0x8620eafad1082e57
    .dword 0x7ebb73be84817165, 0xbb878d14bca081f
    .dword 0xf42686bfd16a1204, 0x564b0e0e35299ccd

    .align 12
data3:
    .dword 0xa6dab9ea9f5f5515, 0x66dbeeeb16d7facb
    .dword 0xd6b1fabb2d3da730, 0xae3f56bcec2d4f1c
    .dword 0xc8d8a6146f212e7d, 0x336cec430b295dbf
    .dword 0x811dbcc6653ffbe8, 0x82c7c33d1a5e859b
    .dword 0xe788043b1d85267a, 0x96091f5d5ce1fe09
    .dword 0xba68c4f36b96474f, 0xf0bc7323c8339d70
    .dword 0x3aa6544a2acc25e1, 0xbb17f6056d76faab
    .dword 0x1ddee07ba710b161, 0xe8b13a79f59106d8
    .dword 0x9c925257f3a8b966, 0x3b8a7aab731a413
    .dword 0x4bd6c27499ddd6b0, 0xa23ca785034f599a
    .dword 0x96aee4ecf9745898, 0xfa74ed5ba4dcbf24
    .dword 0x1a264ca7411a3a8b, 0x92d658821f75262c
    .dword 0x2ec3109162f4c4f0, 0xe80a187793806a34
    .dword 0xac1a4efb436027ae, 0x6ceb9ef7c2e51d7f
    .dword 0xe8566a3e9c383e51, 0x61b3d1c5201b7359
    .dword 0x9581c549cc1723a9, 0x3585c5a62a50049
    .dword 0xedc4d27ed8ae5eb6, 0x2810267da53175
    .dword 0x921c82d423070d20, 0xbc89d5a3f8f45e1c
    .dword 0x76cf84d13a3aa762, 0x691cf511c200ce23
    .dword 0x6c983bf9b6a5b067, 0x4d0db7e842a30b0f
    .dword 0x42883bae89a6b2a7, 0x467e3a4a24ade7be
    .dword 0xc61b31ea59969f19, 0x3830bd734aebc900
    .dword 0xc5630f4890372a90, 0xd7735bad13362aa4
    .dword 0x86468734f86cfec9, 0x3bf92c11de41d540
    .dword 0x80af02a45dfb57a6, 0x1e7e00df8cb1155d
    .dword 0x29aa2b2b9c7cb326, 0x62c34ea47ed9e983
    .dword 0x76b946888ddd8c89, 0x5f4343abc72ae32
    .dword 0x2f7dc6252692b3a, 0x9e668844e55a2f87
    .dword 0xbc59c3b075f8231a, 0x6c917ddab0cdb7ce
    .dword 0xcf97d2363f2fd3a1, 0xb5c20abbc9d8701b
    .dword 0xd7b88605e71a3269, 0x98b71baf8b41bae
    .dword 0xbfb573424c7fc54e, 0x9fec938a97b45991
    .dword 0x637248a74511d85d, 0x61aa86cd9511a36a
    .dword 0x1981f55b2727f3c9, 0xec5feb20032ac24b
    .dword 0x5f9e4dd97339316d, 0x60ab9976d23591b9
    .dword 0x4e40ea69379e6cc5, 0x66027591983064e5
    .dword 0x92edaa2ebb06ef0b, 0xce34032d589e2cd2
    .dword 0x60940ccd98c1188c, 0x62614e1c0cc16f6f
    .dword 0x1d2c05fb18a00ce9, 0xb0a3593d813623ea
    .dword 0x396889a1f6ade887, 0x2482691d16a5ab6b
    .dword 0x62694bd81c8e7043, 0xd8e2856372f90d2b
    .dword 0x5b9feae0b660c1cb, 0x99345f2d7c7de459
    .dword 0x9980155868fd9e38, 0x72a5938baaad986c
    .dword 0x5b3f86ca22023c49, 0xd28cac1a0587e80a
    .dword 0x7aae9c5b61e47f8d, 0x859201fcc259b3bb
    .dword 0x415c1b07906a8573, 0x2acc2e470361eb09
    .dword 0x2c3c6fcef41e40d5, 0x11b0b57ef219a5d5
    .dword 0xa9ab6c9c05b887d7, 0x9c618aedd7a060c0
    .dword 0x1470972b3965be44, 0x7e07d2911b14f5f1
    .dword 0xadb13bf09ccc378, 0x7d98f98aa7ff7c7a
    .dword 0xb080de338be4f653, 0x48783b6da22e64fb
    .dword 0x800f9845bc3d7c61, 0x6210bfaf8074cf0e
    .dword 0x3b9f66e24072cae2, 0x21f317b3ad349889
    .dword 0x94b7a1a569c1c829, 0x8219eaec306b03a8
    .dword 0xf1419086207dcd40, 0x6b020edf91d3e338
    .dword 0x4bd09d4e561cc4a8, 0x5ba26b46ee524ed3
    .dword 0x8d028aeab194d88b, 0x9cbabe5ca02f03e2
    .dword 0xe6f445cbd441496f, 0x5dd0dd81fd62f11e
    .dword 0x674639c74fdef907, 0x380dbdc802ab6333
    .dword 0x82eadcc2010f1d8e, 0xc366e6af5e162671
    .dword 0xba344367d1057c5b, 0x121493898a81cdf8
    .dword 0xbc3d518ecab393ef, 0xee8feb7a327fe39e
    .dword 0x3850d311a96059c0, 0x59d6eea67b85ccfa
    .dword 0x6578239d24a44df9, 0xd5d3f0fcf1aa381c

    .align 12
data4:
    .dword 0xaa79b5072103face, 0x440844b1d7f7d79b
    .dword 0x6fc7c3c6b5437b7d, 0x9643f70fe3ac1c2d
    .dword 0xe849164a16123ec6, 0x5ae2d13c36dc8f60
    .dword 0x62409fac6e60f6d1, 0xda890e2e77255405
    .dword 0xafacf36fff02d4da, 0x70864ec3d2895194
    .dword 0xba6c640ba843f66c, 0x98ce7ff31dd262d4
    .dword 0x68b2f16affeee6c8, 0x49d6550aac936140
    .dword 0xc1c02fb4b3cdaf4b, 0x15e77047bbbbe8cf
    .dword 0x8ed192dd4c828ef0, 0xb6999507e63236f0
    .dword 0xa22ae1c1b4d8f6eb, 0x229c75dfc5f1ae1b
    .dword 0x59d46562516e3d8c, 0xb3e42f6d9a33e5c4
    .dword 0x352e6204fe993b08, 0x4315c12319f719bd
    .dword 0xb745750c16497ed2, 0xf93c2e3633fbb6f4
    .dword 0x8489f514d3488530, 0x384da370f12156f0
    .dword 0xaba372c26b688304, 0x3627ea675534479
    .dword 0x22f3a44dc0a4a591, 0x871f021899e24759
    .dword 0x9a4644b5b6a990d9, 0x27992def715f0afe
    .dword 0x6bbf81cfe08c9e75, 0xe73f108d9b249d73
    .dword 0x64b6755393eea8d4, 0x5ec05676222c16c9
    .dword 0x96b4bacfb353f5d6, 0x28472468cbb5f8d7
    .dword 0x257e15d9dad21c0d, 0x3b2fea20131dbdcd
    .dword 0x2039246115219941, 0x7c0071b40375d301
    .dword 0x9194fee9474486e8, 0x5c4ed2afca56fb18
    .dword 0x62440640fb75fc8b, 0xf8dc8167e9a322a3
    .dword 0xc067a92f45393110, 0x73dd6dd97551d6d1
    .dword 0x8987eb492256abb4, 0x22d5631491e149c7
    .dword 0x349eec87c0516e6e, 0xefffde85459943a
    .dword 0x223bae1c2437d9f6, 0xd74f0c7a37911b2e
    .dword 0xcc36203a15a4e884, 0xe57a7083fb783e57
    .dword 0x7af663e3453e742c, 0xb5569ad66526a266
    .dword 0xa8dfe7cd1bca2924, 0xb6b9eb8e5bb6efe8
    .dword 0xc1460839033e6f74, 0xb79bb653baf1e62c
    .dword 0x5bc77e0f3fd1c272, 0xd2a496d24e440add
    .dword 0x2fad7236526c049, 0xd5ac6dfd52a3858
    .dword 0xc01c4787e16dc637, 0xe145f9c14b861b07
    .dword 0xee9b98c48b382bbd, 0xcee2211cc3a768e7
    .dword 0x6ed3f480a4bc7f55, 0xf1d35224cb252be9
    .dword 0x4cdd395e12d84b78, 0xbb273ff6e5da416f
    .dword 0x1176ab9db39c813c, 0x458b7289dffcdb03
    .dword 0xc690442fc8fcbd05, 0x852cb938c8bdac50
    .dword 0x4bb675fdeb5c94ff, 0x581d2aba7f6e2495
    .dword 0x6d1c39a8cbd8efde, 0x25f1c9662f3a8e7b
    .dword 0x90cfc009925eba6d, 0x5ecbd242c951d3aa
    .dword 0xbe937ea8386c3d34, 0xe299e04c0510b23c
    .dword 0x60e1872d64e68a6f, 0x8a267d91c833ca32
    .dword 0xb923412782cb3545, 0x5254a8113a99d677
    .dword 0xf3c017c332ec308e, 0x633d56fb529350a8
    .dword 0x8b25ad04d3caf30e, 0x5c0ce845fae1fa75
    .dword 0x8c13afe11279e96, 0x9c5859c6026601a8
    .dword 0xdc203a2282c369c8, 0xea4951d21a82f905
    .dword 0x5216bc0f0f9b98dd, 0xcc55697a18b34f48
    .dword 0xb5b655b720e50131, 0x4c1133185402fb6d
    .dword 0xaed446e35b4c8366, 0xc05c31f205d5f240
    .dword 0xf395a0e79e2c5dbe, 0x939aaefa85697689
    .dword 0x74f1d9da644f0879, 0x467049062bc4391d
    .dword 0x8803334bd8c48f20, 0x9186d463ab30adad
    .dword 0xf492ccd10ea2aafa, 0x979b3f915a4f12a4
    .dword 0xd1681c53a7224ac2, 0x31cbb5752615b2e6
    .dword 0x9ef04592f0b65ac3, 0x7cf5df17b50e2761
    .dword 0xd7217cc78689ca2f, 0xf3aa95b07bb76b85
    .dword 0xfc468e89519338c5, 0x7778085157711409
    .dword 0x530d2d4358cad63a, 0x613e6fe790b6b2a6
    .dword 0xaa4552ee5c1ad887, 0x966cfb9c0555ecb2
    .dword 0x932bade5086fc9a0, 0x650b53951a5d6242

    .align 12
data5:
    .dword 0xd37b8ab3b0febe43, 0xfa8210f7032a22ce
    .dword 0xed5aa0ae36d78ad2, 0xac925021e3769cbf
    .dword 0xf3805549566270e0, 0x98c0aa46084b52a3
    .dword 0xdb0fefe40e025f4, 0x8e9f3b7817913772
    .dword 0xf17678af2e5500da, 0xd79966625260121a
    .dword 0x1e86be345c72f17c, 0xd2d2c026c37545b4
    .dword 0x78fefdfd2347db55, 0xbae78868c1b313de
    .dword 0x63d1bcd2122887d4, 0xd7b863c271b81d45
    .dword 0x8c9ccde176306652, 0xb2aa3f5b1044d0d6
    .dword 0x240ff472d710b5af, 0x69da570945b6e09c
    .dword 0xd634afc36469e2d6, 0xabc4e8189e737404
    .dword 0x523fddb105583a42, 0xca8c7d8fb523ed63
    .dword 0x98e21966f6a37c89, 0xf316ab351fe3cae0
    .dword 0xc67008a7642c6130, 0xeb210728018ec861
    .dword 0xb8e04f78a45aab8c, 0xbe7f09cd8d22b865
    .dword 0xeda564473b663164, 0xc26b2dbd286a5f8b
    .dword 0x1b73a3f3cf8816a2, 0x28bee10725b97601
    .dword 0x1cf1fd2c9a527b90, 0xdd8d087d60b0a734
    .dword 0xa5546e4ac47888ae, 0xfbc9580e096fb7f7
    .dword 0x57449ef467a559b5, 0x35a38a74768fd2bf
    .dword 0x6cfbf77e3b3abace, 0x920c6da19afd8801
    .dword 0xa6d80b7d36e5981b, 0x84225afff8301423
    .dword 0x138eed5266add7b4, 0x2309c19c119c3867
    .dword 0x425218234b5a4981, 0xeb93f7172e289850
    .dword 0xee6010a8f91bbdf3, 0x2407a76bcfd995f9
    .dword 0x38c9dc37037c603d, 0xd5efb21118ce719d
    .dword 0x117b1654e92f5391, 0x488546bb499336f2
    .dword 0x5dde2cd5ba12995b, 0xf95a7384b5586790
    .dword 0xa33ceaacb782777f, 0x1c5673a3367a3bf7
    .dword 0x29c2578b752038cc, 0x54ed44f909ff23db
    .dword 0x43f09ec07e4c6032, 0x3a73856fb0a0f3c4
    .dword 0xaba20b31e1709c99, 0x99c40cfc5f75b3a1
    .dword 0x82c83e9f651a8378, 0xf8e2b53ade521c65
    .dword 0xf51abc608d5612ab, 0xd32004b3b92cd6b1
    .dword 0x35aa825d32806858, 0xdfc0cffe07bf808a
    .dword 0x349ac34c6bbebc2e, 0x7c4000b863677e68
    .dword 0xa798cb400c184003, 0x2f27bb1118e996af
    .dword 0xd5931f47f6fae23b, 0xcb14897437777802
    .dword 0xcf9fbe0006d50e91, 0x9da1ce23351386a1
    .dword 0xd5e8184dd200c475, 0x9f3d732f080dd62b
    .dword 0x8b3aca91a1436d55, 0x58c2ac41507d055c
    .dword 0x994e4b42e4f2eb1c, 0x92397c2635cf81b5
    .dword 0x30c7651d6735224c, 0x5c21e721542cd9a
    .dword 0xd62a22dc534671c3, 0x6309486b6231c8ab
    .dword 0x5e1aa48ae12ee7a0, 0xb673ef612ab7b5ac
    .dword 0x2f10eef7b2e7cc12, 0x9689aaea85b02d7d
    .dword 0x88e80012bee8fbed, 0x7d1b92986f44159b
    .dword 0xd44104c141db9677, 0x2e0410332eba4718
    .dword 0xefc505fe9df880b5, 0x794751da1a0e71ca
    .dword 0x11316078628e9fee, 0x5d823b7b09c6d2f3
    .dword 0xb8ce247c95e5ba5c, 0xa7f1e0b7452b1cbb
    .dword 0xbf5df9eeca532e4c, 0x97f143361c1f8dd3
    .dword 0x44091ac9100d72b7, 0xccfad3f7bbab891
    .dword 0x3faaced7d5724c9, 0x6fff218c7899477e
    .dword 0xfb5e605ca18e5679, 0xcfdaf2ad396382da
    .dword 0x78f7dc4e34db6739, 0x186140b751b519ca
    .dword 0xb4d992406e7951ee, 0xe55f74565c0296e6
    .dword 0xb5b1703322c12ed, 0xf192bc457e555df8
    .dword 0xb2f4ebcffd76d53e, 0x3c7c2262d4870c48
    .dword 0xfb1fbe21eac6074, 0x58b48a3cea03f899
    .dword 0x44f3e67a7d0660e, 0x889f27eef69581b8
    .dword 0xd667f8644fb9db79, 0xc00f85f946bcf320
    .dword 0x3eefd9e628a7bcf6, 0xd2a2faf3c72d7d26
    .dword 0xe52ccba04947ec6a, 0x1fe5d90f8c9f69c7

    .align 12
data6:
    .dword 0x56b5e87ee99c1403, 0x2788046da6ace22
    .dword 0x186ed0e8d4ef36a1, 0x5048eebbc177b295
    .dword 0x3fcd39622da6fd52, 0x1f78b7129bbb6b08
    .dword 0x675c826bd44c4221, 0x563896846a39aeb2
    .dword 0x56616fb0f5a93cb6, 0xfeccefbcdf439e86
    .dword 0xc6342e93f008ffdc, 0x47bab6b7810539bb
    .dword 0x7ce9acf2814dbb0b, 0x8fc4de915df15d05
    .dword 0x356f32f7bd478f59, 0x43245cb8e3115607
    .dword 0x3dbf3701b2fb96c, 0x916ec0b04396dcac
    .dword 0xeb07b6b03ba6eedd, 0xce9b579baa336e7b
    .dword 0xfeb756d5b705f210, 0xd496239b15aca066
    .dword 0x2a7c7d49c733109e, 0x30c16d1816e7fc28
    .dword 0x837d21c248d90224, 0xf337f3903d0bc94f
    .dword 0x99d53e00ba083684, 0xdcadc64745de68d2
    .dword 0xe0ce3187b4e78fb4, 0xb7f6435c075ad5bf
    .dword 0xd038190a2dc1d138, 0x71a7ead30c94e6d4
    .dword 0xb7b1941a715fbd48, 0x1728acf278f23efc
    .dword 0xa18f630ae5dfd8e0, 0xda85dc54a5b12a53
    .dword 0x7ff6f9885301f81e, 0x7ab28aa2f46c11e3
    .dword 0xbcc26e40b4e5a535, 0xf51461abc56f33d1
    .dword 0x78ac2d47f58c8a90, 0xed3088838d8bba3c
    .dword 0x4d566e76c3aa396f, 0xabede3eb3a9bec24
    .dword 0xe95c21d27a8331f3, 0x80dbef313465e3cd
    .dword 0x678caed8c8f0604a, 0x10da21b77551f882
    .dword 0xf78d38bc925e2909, 0x8cc0357bcf573d3
    .dword 0x445517d19a2c7cf2, 0x43da76a6dcff46d8
    .dword 0xdd2a4d511c655914, 0x60f7bbf65635a893
    .dword 0xfc44152563a1bb6, 0x44f14bc852474a30
    .dword 0x3611901180a75b10, 0xb95e5a4a3c8d8c5f
    .dword 0xc351b704969f1677, 0xb4f2b21a9d40b055
    .dword 0xa0fee9b05ff02679, 0xc531ddbb03138c79
    .dword 0xab8f487570099e99, 0x2719924b0bde320e
    .dword 0xbf68a6b047679798, 0xd8c0de57c45051e1
    .dword 0x5c04c52e268adacd, 0xad19091ca2c58ac9
    .dword 0x64c9e0f3ca7e9d57, 0xb78404dec5071ce8
    .dword 0x71f82edd764e069e, 0xc83129ee83663d25
    .dword 0x75e8e5fea23a18fd, 0x9eb211b9e9bd84fe
    .dword 0x2b85d78908108d60, 0xa89533c0a88028dd
    .dword 0xee64b6d374ef6129, 0x83b7a70b42ff5a0c
    .dword 0x7c5ade25c48c5f96, 0x245b8ba67c68bd1f
    .dword 0xde8b2127356dade5, 0x74cac1c2638919ec
    .dword 0x2d379ade5c3c6ef7, 0xdd67fb401fd578b9
    .dword 0x731c9ea9e818ecec, 0x840f351ff03a3582
    .dword 0x7dbcd0ddcd77faf5, 0x7299c9d651c27cc0
    .dword 0x7d2c154a1c5cede8, 0x71b8df0a6a953353
    .dword 0x6d1ab64a114e4f75, 0x1974c4d971678762
    .dword 0x21a1a118cf6032d1, 0x7e2185fa3d0871a3
    .dword 0x70f40e25fe5fc9d7, 0x8b4a3cb87e9e9c82
    .dword 0xa78a2606d5f0532b, 0xd4d6966041acfe4
    .dword 0xf22f48df5c133f12, 0xf98c73cdab083723
    .dword 0xfdf38fabf1905973, 0xd0415ca581e33ea6
    .dword 0x1c8bef3228c95951, 0x3d9bad44cf461898
    .dword 0x2eb3c0ae73a9d337, 0xde5339885d5bb9fc
    .dword 0xf03a2619d1b5740c, 0x8305bea6460c7184
    .dword 0x8327a195c1deaf86, 0xc5fd7f733e49ba9f
    .dword 0x7f1941021219c396, 0xf5d192eb11b185ca
    .dword 0x52401e57c2ff9abc, 0x6ce1a131070a353
    .dword 0x9fd40c1fc1670b12, 0xe732c61357108ad2
    .dword 0x8865c4a654718883, 0xd3a37e156f1e79c2
    .dword 0x7eee1a887b349cbf, 0xbd9bd83109e83bbb
    .dword 0xe61e589ecd243fbf, 0xbb205f2d6b903274
    .dword 0xd981610cfb737baf, 0xbf8565407ce3fc58
    .dword 0x6c541d4f012af7c0, 0x28daef6a3272c226
    .dword 0x4363cf0bac9bb2f9, 0xc2086959543ab8cf

    .align 12
data7:
    .dword 0xb4ff3b3f3f8ebd18, 0x3edc0b7411c477bd
    .dword 0xafd47ac58fa68aab, 0x291fc6d433f9250d
    .dword 0x5dd9b4467291f7a9, 0xbeff52d72f4203a4
    .dword 0x756283068ce457bd, 0xaed330ab5749968
    .dword 0x175247add3a732d, 0xedd6578ebd6440e6
    .dword 0x9c9375c38fdb05e4, 0x2df452e2f5992440
    .dword 0xf660a188c2dc9811, 0x3df2dc8418d1c660
    .dword 0x1405e9d78a2e39d9, 0x168cb57b1a3a68d3
    .dword 0x2b231bb88c44646c, 0x59d3e5bfc8d31527
    .dword 0x82c731b91f9e5c47, 0xcc76dfbd542900e7
    .dword 0xce4ba9560d6b3244, 0xa848abef444c09d1
    .dword 0x83a6637426026ac8, 0x6899b0b90a71f6ba
    .dword 0x9c02b4c416157967, 0x467003e2cf53e0f2
    .dword 0x3b3e3f1ece051dbe, 0x182a29d269ddb3b5
    .dword 0x8c07a8d2c43ae885, 0x625000b22d188e94
    .dword 0xb3f3ec737c365cb1, 0x963729523d264f49
    .dword 0x617842586686fb4b, 0x86deaae26cb48c60
    .dword 0xaf8b04d1d8a85cf7, 0x60c8e1420bd21104
    .dword 0xbefefc4c73b5a788, 0xbb931fa627e8b848
    .dword 0x1c2f758ace242b59, 0x89552209d578d80c
    .dword 0x40b5bdbf2c46ae44, 0x10630419da33d7ad
    .dword 0x62cc036196beeda6, 0xbf267b1529e745b6
    .dword 0xf91fa3887e5c07f, 0xa5fd524ffa48f718
    .dword 0x552949b1f43264ea, 0x326c08de454e10a2
    .dword 0x6632e43e2c6fa4df, 0x8d8b03517213cf3a
    .dword 0x26679f6c4bb59c10, 0x61632fb8e0dc263
    .dword 0x8649458feeaf89e6, 0x7dba67a8205c1483
    .dword 0x87c220fc1a1c4c29, 0x9b7cdd2e66aaadfd
    .dword 0xf13f0f38ce65b030, 0x1caa16ed3707325a
    .dword 0xf4891ea63992cac4, 0x73b29f2df3925a46
    .dword 0xede95f8ffb531ba8, 0x4ef537373bca980a
    .dword 0x74334d874ebfc3eb, 0x31dd908b072ccd58
    .dword 0xd22a8ca386de9d70, 0x28bac160947947d
    .dword 0x57994d01a7383d71, 0xbe19ad4e0873b4ec
    .dword 0x654ee034b3a7efce, 0x6fca8c1bff2a6edd
    .dword 0x959c74066a6bca84, 0x9e299c5f048dd2b0
    .dword 0xae4e997a4e8b10e3, 0x1a53e903db15f1ef
    .dword 0x740d0774ce6176fd, 0xd8e5e252da4051b6
    .dword 0x97c56c04b3dc58ba, 0xe1eb4645a25de476
    .dword 0x6ebfb80843623cc, 0x40ea837fa02ad8f4
    .dword 0x6f13e751caab2718, 0x361733b7cc6d9f49
    .dword 0x7d5b1c9854f243fd, 0x17456966a28b3329
    .dword 0xdcb05f708c917d55, 0x639268c73ceefbd8
    .dword 0xbb3e5ec2edd8485e, 0x472da995ea9b82eb
    .dword 0x31facccefef1f92a, 0x6d57e2f27fb0ae9c
    .dword 0x9aff8e1ba9c3d107, 0xa60c2a4749fb0b75
    .dword 0xb70564c9e568b027, 0x808754ae2f141e54
    .dword 0x4f5c38a6788f2e75, 0x6977fa6d5daadb2a
    .dword 0xf63d1088827b4ed9, 0xf2203a1850f3c9
    .dword 0x38ee29547630afee, 0x3ebc5f7d9db46e25
    .dword 0x279d9f37b8cb7994, 0x2dd21de0c25e7a44
    .dword 0x4c7559588537352d, 0x9686664d107737b9
    .dword 0x9ee67d33d473ba07, 0xac6d3b6dfaa1c213
    .dword 0xd6ee41c5bfdd518a, 0x45be4bca98115596
    .dword 0xef93618f716de117, 0x238198e34dfbf936
    .dword 0x6271089468d9c377, 0xe9db8a4fda9ceb38
    .dword 0x79947e19a2141b4c, 0x24e5b008e8bc88c4
    .dword 0x3c3314c88b9fce60, 0xcf56c48cc4baeb54
    .dword 0x686b99c4fc685fa2, 0xfa3fad979d40f0e5
    .dword 0x96ced8cf15fdd97b, 0x28dcbf5a3df6ea61
    .dword 0xc354f0daa568f578, 0x848e523cb2e177e6
    .dword 0xf9a40d75f2ae1eff, 0xa6ed25a606c82b3e
    .dword 0x97170d09c6e75466, 0xb620b15064e81841
    .dword 0xa648209ab4b2aed9, 0xad1f7cbf3f9dd299


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
