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
pfx.bb0.l0:         andi x21, x21, 0x3f8                      
                    la x19, data1                             
                    add x21, x21, x19                         
                    fld f0, 24(x21)                           
pfx.bb0.l1:         andi x22, x22, 0x3f8                      
                    la x21, data7                             
                    add x22, x22, x21                         
                    fld f1, 8(x22)                            
pfx.bb0.l2:         andi x22, x22, 0x3f8                      
                    la x20, data3                             
                    add x22, x22, x20                         
                    fld f2, 8(x22)                            
pfx.bb0.l3:         andi x18, x18, 0x3f8                      
                    la x20, data1                             
                    add x18, x18, x20                         
                    fld f3, 0(x18)                            
pfx.bb0.l4:         andi x21, x21, 0x3f8                      
                    la x20, data0                             
                    add x21, x21, x20                         
                    fld f4, 16(x21)                           
pfx.bb0.l5:         andi x20, x20, 0x3f8                      
                    la x18, data2                             
                    add x20, x20, x18                         
                    fld f5, 16(x20)                           
pfx.bb0.l6:         andi x21, x21, 0x3f8                      
                    la x19, data6                             
                    add x21, x21, x19                         
                    fld f6, 8(x21)                            
pfx.bb0.l7:         andi x18, x18, 0x3f8                      
                    la x19, data5                             
                    add x18, x18, x19                         
                    fld f7, 24(x18)                           
pfx.bb0.l8:         andi x19, x19, 0x3f8                      
                    la x21, data6                             
                    add x19, x19, x21                         
                    fld f8, 0(x19)                            
pfx.bb0.l9:         andi x20, x20, 0x3f8                      
                    la x22, data2                             
                    add x20, x20, x22                         
                    fld f9, 0(x20)                            
pfx.bb0.l10:        addi x18, zero, 264                       
pfx.bb0.l11:        addi x19, zero, 705                       
pfx.bb0.l12:        addi x20, zero, 681                       
pfx.bb0.l13:        addi x21, zero, 455                       
pfx.bb0.l14:        addi x22, zero, 1979                      
pfx.bb0.l15:        addi x23, zero, 422                       
pfx.bb0.l16:        addi x24, zero, 1242                      
pfx.bb0.l17:        addi x25, zero, 1776                      
pfx.bb0.l18:        addi x26, zero, 129                       
pfx.bb0.l19:        addi x27, zero, 883                       
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
prp0.entry.l0:      jal x20, prp0.bb3                         
prp0.entry.l1:      fsqrt.s f4, f0, rup                       
prp0.entry.l2:      fcvt.d.w f3, x20                          
prp0.entry.l3:      fnmadd.d f4, f2, f3, f0, rmm              
prp0.entry.l4:      srli x20, x19, 2                          
prp0.entry.l5:      fsgnj.s f2, f3, f1                        
prp0.entry.l6:      fdiv.d f1, f2, f3, rup                    
prp0.entry.l7:      sraiw x22, x18, 13                        
prp0.entry.l8:      blt x21, x22, prp0.bb3                    
prp0.entry.l9:      bge x18, x19, prp0.bb3                    
prp0.entry.l10:     bne x18, x22, prp0.bb3                    
prp0.bb0:
prp0.bb0.l0:        fadd.d f0, f2, f3, dyn                    
prp0.bb0.l1:        bge x22, x21, prp0.bb1                    
prp0.bb0.l2:        add x20, x19, x22                         
prp0.bb0.l3:        fmv.x.w x21, f2                           
prp0.bb0.l4:        call fn2                                  
prp0.bb0.l5:        lui x18, 266                              
prp0.bb0.l6:        jal x21, prp0.bb3                         
prp0.bb1:
prp0.bb1.l0:        andi x18, x19, 1317                       
prp0.bb1.l1:        fcvt.s.wu f0, x19                         
prp0.bb1.l2:        fcvt.d.lu f2, x19                         
prp0.bb1.l3:        ori x22, x20, 395                         
prp0.bb1.l4:        fcvt.s.wu f4, x20                         
prp0.bb1.l5:        fcvt.s.w f3, x18                          
prp0.bb1.l6:        bge x19, x21, prp0.bb3                    
prp0.bb2:
prp0.bb2.l0:        fsub.d f2, f4, f0, rup                    
prp0.bb2.l1:        lui x20, 3723                             
prp0.bb2.l2:        andi x20, x21, 1899                       
prp0.bb2.l3:        call fn1                                  
prp0.bb2.l4:        divw x20, x21, x19                        
prp0.bb2.l5:        divu x19, x18, x20                        
prp0.bb2.l6:        fcvt.d.w f2, x21                          
prp0.bb2.l7:        fmsub.d f1, f4, f0, f2, rmm               
prp0.bb2.l8:        beq x18, x21, prp0.exit                   
prp0.bb2.l9:        call fn0                                  
prp0.bb2.l10:       bne x22, x21, prp0.bb3                    
prp0.bb3:
prp0.bb3.l0:        remw x19, x21, x22                        
prp0.bb3.l1:        fclass.s x21, f4                          
prp0.bb3.l2:        fmax.s f0, f2, f3                         
prp0.bb3.l3:        beq x22, x21, prp0.exit                   
prp0.bb3.l4:        fsqrt.s f3, f1, rup                       
prp0.bb3.l5:        fnmsub.s f0, f1, f3, f4, rmm              
prp0.bb3.l6:        fsgnjx.d f1, f2, f0                       
prp0.bb3.l7:        fsqrt.s f4, f0, rne                       
prp0.bb3.l8:        feq.s x18, f0, f2                         
prp0.bb3.l9:        beq x22, x19, prp0.exit                   
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      fsub.d f2, f0, f3, rmm                    
prp1.entry.l1:      call fn1                                  
prp1.entry.l2:      fclass.d x19, f3                          
prp1.entry.l3:      sltiu x21, x20, 1457                      
prp1.entry.l4:      la x21, prp1.bb0                          
                    jalr x18, 0(x21)                          
prp1.entry.l5:      fmv.x.d x18, f0                           
prp1.entry.l6:      mulhu x21, x18, x20                       
prp1.entry.l7:      sub x20, x18, x22                         
prp1.entry.l8:      slliw x22, x20, 24                        
prp1.entry.l9:      bne x21, x20, prp1.bb4                    
prp1.bb0:
prp1.bb0.l0:        call fn2                                  
prp1.bb0.l1:        remuw x21, x20, x18                       
prp1.bb0.l2:        fcvt.s.w f4, x21                          
prp1.bb0.l3:        beq x18, x21, prp1.bb1                    
prp1.bb0.l4:        fcvt.d.wu f2, x20                         
prp1.bb0.l5:        fsgnjn.s f2, f1, f3                       
prp1.bb0.l6:        blt x18, x19, prp1.exit                   
prp1.bb1:
prp1.bb1.l0:        sub x22, x21, x20                         
prp1.bb1.l1:        call fn1                                  
prp1.bb1.l2:        fmin.s f0, f3, f4                         
prp1.bb1.l3:        fmsub.d f1, f0, f3, f2, rup               
prp1.bb1.l4:        fmsub.d f0, f3, f2, f1, rup               
prp1.bb1.l5:        blt x22, x20, prp1.bb2                    
prp1.bb1.l6:        fcvt.d.s f0, f0                           
prp1.bb1.l7:        call fn2                                  
prp1.bb1.l8:        bge x21, x19, prp1.bb2                    
prp1.bb2:
prp1.bb2.l0:        divuw x22, x21, x18                       
prp1.bb2.l1:        fmul.s f1, f3, f2, rdn                    
prp1.bb2.l2:        sltu x21, x20, x19                        
prp1.bb2.l3:        lui x19, 2987                             
prp1.bb2.l4:        slli x22, x19, 62                         
prp1.bb2.l5:        fcvt.s.w f2, x20                          
prp1.bb2.l6:        call fn3                                  
prp1.bb2.l7:        bge x19, x22, prp1.bb3                    
prp1.bb2.l8:        fmin.d f0, f3, f2                         
prp1.bb2.l9:        bne x18, x20, prp1.bb3                    
prp1.bb3:
prp1.bb3.l0:        fcvt.l.s x21, f3                          
prp1.bb3.l1:        fence.i                                   
prp1.bb3.l2:        beq x21, x19, prp1.exit                   
prp1.bb3.l3:        addi x21, x18, 1752                       
prp1.bb3.l4:        fadd.d f0, f3, f2, rup                    
prp1.bb3.l5:        sltu x18, x22, x20                        
prp1.bb3.l6:        bne x20, x22, prp1.exit                   
prp1.bb4:
prp1.bb4.l0:        fle.d x18, f2, f3                         
prp1.bb4.l1:        fcvt.d.w f1, x19                          
prp1.bb4.l2:        fmsub.d f2, f1, f4, f3, rup               
prp1.bb4.l3:        andi x19, x20, 1429                       
prp1.bb4.l4:        fcvt.wu.d x22, f1                         
prp1.bb4.l5:        fle.d x18, f1, f2                         
prp1.bb4.l6:        fdiv.d f2, f4, f1, rup                    
prp1.bb4.l7:        fsqrt.d f2, f0, rdn                       
prp1.bb4.l8:        jal x20, prp1.exit                        
prp1.bb4.l9:        bgeu x22, x18, prp1.exit                  
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        and x18, x22, x20                         
tc.entry.l1:        andi x21, x18, 1195                       
tc.entry.l2:        andi x20, x20, 0x3f8                      
                    la x19, data4                             
                    add x20, x20, x19                         
                    amoswap.w x18, x22, (x20)                 
tc.entry.l3:        andi x20, x20, 0x3f8                      
                    la x22, data1                             
                    add x20, x20, x22                         
                    amoand.w x18, x21, (x20)                  
tc.entry.l4:        fmadd.s f1, f2, f4, f0, rdn               
tc.entry.l5:        andi x20, x20, 0x3f8                      
                    la x19, data1                             
                    add x20, x20, x19                         
                    amomin.w x18, x21, (x20)                  
tc.entry.l6:        or x20, x18, x22                          
tc.entry.l7:        fnmadd.s f1, f2, f4, f0, rne              
tc.entry.l8:        bge x18, x19, tc.bb0                      
tc.bb0:
tc.bb0.l0:          andi x22, x22, 0x3f8                      
                    la x19, data5                             
                    add x22, x22, x19                         
                    amomax.w x18, x20, (x22)                  
tc.bb0.l1:          andi x18, x18, 0x3f8                      
                    la x22, data4                             
                    add x18, x18, x22                         
                    amoxor.w x19, x20, (x18)                  
tc.bb0.l2:          fcvt.wu.d x21, f0                         
tc.bb0.l3:          andi x21, x21, 0x3f8                      
                    la x18, data7                             
                    add x21, x21, x18                         
                    fsd f3, 8(x21)                            
tc.bb0.l4:          fsgnjn.d f4, f2, f0                       
tc.bb0.l5:          mulw x21, x22, x20                        
tc.bb0.l6:          call fn2                                  
tc.bb0.l7:          call fn2                                  
tc.bb0.l8:          fle.s x22, f0, f4                         
tc.bb0.l9:          la x18, tc.bb1                            
                    jalr x21, 0(x18)                          
tc.bb1:
tc.bb1.l0:          andi x19, x19, 0x3f8                      
                    la x18, data0                             
                    add x19, x19, x18                         
                    fsw f0, 4(x19)                            
tc.bb1.l1:          sub x19, x20, x21                         
tc.bb1.l2:          mulw x19, x20, x18                        
tc.bb1.l3:          fsgnjn.d f0, f1, f2                       
tc.bb1.l4:          fmv.x.w x18, f0                           
tc.bb1.l5:          fcvt.l.s x20, f3                          
tc.bb1.l6:          andi x19, x19, 0x3f8                      
                    la x20, data2                             
                    add x19, x19, x20                         
                    amomaxu.w x18, x21, (x19)                 
tc.bb1.l7:          andi x21, x21, 0x3f8                      
                    la x20, data7                             
                    add x21, x21, x20                         
                    amoand.d x19, x18, (x21)                  
tc.bb1.l8:          bltu x20, x18, tc.bb3                     
tc.bb2:
tc.bb2.l0:          andi x20, x20, 0x3f8                      
                    la x18, data3                             
                    add x20, x20, x18                         
                    fsd f3, 16(x20)                           
tc.bb2.l1:          fsgnj.d f4, f0, f1                        
tc.bb2.l2:          andi x18, x18, 0x3f8                      
                    la x20, data4                             
                    add x18, x18, x20                         
                    amoand.w x19, x21, (x18)                  
tc.bb2.l3:          fmax.s f2, f0, f4                         
tc.bb2.l4:          flt.d x22, f2, f1                         
tc.bb2.l5:          fcvt.d.l f3, x20                          
tc.bb2.l6:          fmadd.s f0, f3, f4, f1, rmm               
tc.bb2.l7:          call fn4                                  
tc.bb2.l8:          sltiu x18, x20, 247                       
tc.bb2.l9:          bne x22, x18, tc.exit                     
tc.bb2.l10:         bltu x18, x20, tc.exit                    
tc.bb3:
tc.bb3.l0:          call fn4                                  
tc.bb3.l1:          andi x19, x19, 0x3f8                      
                    la x20, data4                             
                    add x19, x19, x20                         
                    amoswap.d x21, x18, (x19)                 
tc.bb3.l2:          fcvt.l.s x18, f0                          
tc.bb3.l3:          call fn1                                  
tc.bb3.l4:          remuw x20, x22, x19                       
tc.bb3.l5:          andi x22, x22, 0x3f8                      
                    la x19, data2                             
                    add x22, x22, x19                         
                    amomin.d x20, x18, (x22)                  
tc.bb3.l6:          bgeu x19, x18, tc.exit                    
tc.bb4:
tc.bb4.l0:          andi x22, x22, 0x3f8                      
                    la x18, data3                             
                    add x22, x22, x18                         
                    amoswap.w x20, x19, (x22)                 
tc.bb4.l1:          fsub.d f0, f1, f3, rmm                    
tc.bb4.l2:          fcvt.d.s f3, f3                           
tc.bb4.l3:          lui x19, 3727                             
tc.bb4.l4:          beq x21, x18, tc.exit                     
tc.bb4.l5:          slliw x22, x21, 18                        
tc.bb4.l6:          la x20, tc.exit                           
                    jalr x21, 0(x20)                          
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
fn0.entry.l0:       divw x27, x23, x24                        
fn0.entry.l1:       div x23, x24, x25                         
fn0.entry.l2:       fmv.x.w x27, f8                           
fn0.entry.l3:       mulhsu x27, x25, x26                      
fn0.entry.l4:       rem x27, x25, x23                         
fn0.entry.l5:       sub x25, x24, x27                         
fn0.entry.l6:       add x24, x26, x23                         
fn0.entry.l7:       sll x26, x23, x27                         
fn0.entry.l8:       fence                                     
fn0.entry.l9:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       fsgnj.d f5, f7, f6                        
fn1.entry.l1:       fcvt.s.wu f5, x27                         
fn1.entry.l2:       ori x23, x25, 1479                        
fn1.entry.l3:       lui x27, 2740                             
fn1.entry.l4:       fclass.s x23, f9                          
fn1.entry.l5:       flt.d x27, f5, f6                         
fn1.entry.l6:       fmsub.d f8, f9, f6, f5, dyn               
fn1.entry.l7:       fle.s x24, f7, f6                         
fn1.entry.l8:       mul x27, x24, x26                         
fn1.entry.l9:       fnmadd.s f7, f6, f8, f9, dyn              
fn1.entry.l10:      ret                                       
fn1.exit:
fn2:
.align 8
fn2.entry:
fn2.entry.l0:       fclass.s x27, f7                          
fn2.entry.l1:       fmax.d f6, f9, f8                         
fn2.entry.l2:       and x24, x25, x23                         
fn2.entry.l3:       srl x26, x25, x23                         
fn2.entry.l4:       fsgnjn.s f6, f9, f5                       
fn2.entry.l5:       fmsub.d f8, f7, f9, f5, rtz               
fn2.entry.l6:       fcvt.d.wu f9, x26                         
fn2.entry.l7:       ret                                       
fn2.exit:
fn3:
.align 8
fn3.entry:
fn3.entry.l0:       fmadd.d f6, f8, f7, f9, dyn               
fn3.entry.l1:       slt x25, x26, x27                         
fn3.entry.l2:       sltu x26, x24, x27                        
fn3.entry.l3:       mulhsu x27, x24, x25                      
fn3.entry.l4:       fsgnjn.s f5, f9, f8                       
fn3.entry.l5:       fcvt.s.w f8, x26                          
fn3.entry.l6:       ret                                       
fn3.exit:
fn4:
.align 8
fn4.entry:
fn4.entry.l0:       addi x24, x26, 1273                       
fn4.entry.l1:       fmadd.d f9, f5, f6, f7, rtz               
fn4.entry.l2:       fsgnj.d f8, f6, f5                        
fn4.entry.l3:       div x25, x26, x24                         
fn4.entry.l4:       fcvt.s.wu f9, x25                         
fn4.entry.l5:       srai x27, x26, 57                         
fn4.entry.l6:       div x24, x25, x26                         
fn4.entry.l7:       fcvt.w.d x24, f8                          
fn4.entry.l8:       rem x23, x25, x24                         
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
    .dword 0xbaa87dadb19cb60a, 0x5a3e79b4e9d06314
    .dword 0xccc9411fecc208d, 0xe14785c98e5b6683
    .dword 0xdcea42fc4e56cf2d, 0x5b96845d212245e3
    .dword 0x4e8090aa2aa45cb0, 0xe9748c5001103c2c
    .dword 0x90cf2875d58610fa, 0x1867ff1b8728ad61
    .dword 0x2b4e2cf29e0d7a08, 0xdc4a5083b8f1f38
    .dword 0x776f5a279d7b3f18, 0x263a045273f9b7dc
    .dword 0xb5a3a46e7cb2221a, 0x1a2c1f080daea318
    .dword 0x552ff37fa2fefde, 0xa234d4bb018d7437
    .dword 0xd644dd174c20dd28, 0xa6c05337be6b99e5
    .dword 0x7065108187a0a38a, 0x19812ec0bf72a23e
    .dword 0x2b3b19ef38e5a238, 0x44b39ba0a34c49a
    .dword 0x99b61da6798be20c, 0x92d5fecc9d42776b
    .dword 0xc4261d02b2745cd4, 0x7602f5152f74c810
    .dword 0x23fe2ff2d5907bc8, 0xfd5a34262c4e86bc
    .dword 0x4e1242df93f568b6, 0x1d1de5ea5a1f9da3
    .dword 0x17baedf7352b16be, 0xb2e7b798ebb9fc91
    .dword 0x7109c2fa1208add1, 0x42ea6412ae3d20ea
    .dword 0x39add431f17a6c32, 0x1c08398a430268e5
    .dword 0x4210bc8d24f61e3d, 0xaa028f7e889e39b8
    .dword 0x740f5bd5f7c9b1df, 0x9c1cdcb0397e4975
    .dword 0x5652ae688ff5c282, 0x5e26aa10c772e5df
    .dword 0x7ffef0a3a43fac96, 0x481e87689511ae23
    .dword 0x148ad05dcc4ef57f, 0x14b05ef530823787
    .dword 0x3fa571a11e6f256a, 0x7b232624c780e1c7
    .dword 0x8a8b4ed728a3f55a, 0xfd711d22a16e3ed2
    .dword 0xf1ccb2d6c7c9cbd, 0x84b9c39e2566c330
    .dword 0x68074bcd8ba96bc1, 0xb257fd84eff8c486
    .dword 0x5acada7e2bc84d5f, 0x80093efa8de6d120
    .dword 0x2dac673231c4b274, 0x6162354d374c8e4e
    .dword 0xa2254e6185c31048, 0xdb03aadc7de36e44
    .dword 0x45e5a8cd5cf0df97, 0x34d8f2403b7334cc
    .dword 0x820d3ef4c3bdc4a2, 0x253a172f6733b2cc
    .dword 0x5dafbf26988bad9, 0x8bd29d304199bd79
    .dword 0x31f6ef395ca2eeba, 0xf2cfe264979cad0d
    .dword 0xbe42a9c7dba1aed2, 0x2c3671de90b1d602
    .dword 0xe5c75a2fc583ce3e, 0xb2b9da52d92e6370
    .dword 0xe0ee6604da3d19d6, 0x15f90cf669aee86f
    .dword 0x6b4a379adcde7e3c, 0x763e2c8ab5a0085b
    .dword 0x7cad99c2d23795c9, 0xa2559eaaadb141aa
    .dword 0xa2aa5771478c72ce, 0x96a17e8ace1cfa73
    .dword 0x8761a8f6f3b915c2, 0x7349fba084d800b1
    .dword 0x146712705d7b6dea, 0x2e166a8dff3075bd
    .dword 0x460b4d87e7b9ad36, 0xd2be29442c96946c
    .dword 0x584d9210e6bbcb8d, 0xf9955506a3b3eb2e
    .dword 0xa14aaa54bd758e6, 0xb745adefbe0da18d
    .dword 0x330f0fefe3c30585, 0x326e65df117588be
    .dword 0xe84017a44f590b96, 0xd9acb92a916aea18
    .dword 0xd0cf82a883daadca, 0x3638685a02deb66c
    .dword 0xd76e1c9603966a56, 0xf82590a29725782f
    .dword 0x6d52b464554ee1f4, 0xd1f57227b80ce93c
    .dword 0x3bfef0b898448280, 0x2ad1b8a50d5e82b2
    .dword 0x18e573153aa9532e, 0x4ad5c97aa94b8b79
    .dword 0x14623e777aea8cdd, 0x470060ec494b8b1e
    .dword 0x8bd60cda439419d8, 0x9c30c3bd7a802ae9
    .dword 0xd18931847e045b19, 0xa3a59e96dc70be97
    .dword 0xb167c9e55de22273, 0xe65237940854650e
    .dword 0x88b7256f1ffe2119, 0x15977f18905df335
    .dword 0x24601804a4ef1288, 0x1303499a8d9bb0e5
    .dword 0x2e746263016d8f50, 0xf8b3d340dbcbdb75
    .dword 0xf58ca1452de91bad, 0xd81b826fdc324ff0
    .dword 0xa3e4aa82e70d96d5, 0xd7bb8aa740e38248
    .dword 0x1ed8c711ae7cbbea, 0x9a4c07434fcf5091
    .dword 0x5d44c3caa6ed9115, 0x40a81c6a123a55e8

    .align 12
data1:
    .dword 0xbc8747bb88bb593e, 0xff6304859b17b1d2
    .dword 0x1eae03247fa1cf15, 0xabcdaf5bff06e401
    .dword 0x922e53710ccedb23, 0xecb613ab65436626
    .dword 0x923d1a1eba099260, 0x1d54a9163b101f1d
    .dword 0xb39645fa3b0c12d3, 0xe2721c5828e02095
    .dword 0xdfb479702403d451, 0xa7c381cdc70d5aac
    .dword 0x8afcc8e63016ffa4, 0x7cd81d08c05ff299
    .dword 0xca6dda5346875327, 0x2cb40e9cd33fe01a
    .dword 0xb17fd544fe8fb1e8, 0x96412a75e1cc6347
    .dword 0x83ffd4cdd045eb57, 0xea8e6a269c429257
    .dword 0x4f75bde5a00d9449, 0x823a6bdecf085422
    .dword 0x191e0838e21014f2, 0xb9f1e3444ef103df
    .dword 0x3066b81f5a24bba, 0xf76ad29240298d36
    .dword 0x62b1efb0e9ac51f9, 0x2230f25a62359aec
    .dword 0x16bb56c5ee69eb60, 0x3002d28d6740ce2d
    .dword 0x764e95b592834b8d, 0xcb4984b4bf216664
    .dword 0x118cc07df14c49bb, 0x945090863f5a92a7
    .dword 0xde4799e897db1fd0, 0x92d0c6a42d90e3fa
    .dword 0x2f1eea55b0305285, 0x17d00f07859bffe1
    .dword 0x9711ea9a422359cd, 0xc5bdcca2d3f235ed
    .dword 0x5906604fa739e0d8, 0xe860f4f32984c0a8
    .dword 0x325fb5d7eb72dda3, 0xa417bcd12497b8a0
    .dword 0x7453ae9f94f00b1, 0x23be04c04883b770
    .dword 0xfabc64d3a96f0d4e, 0xd2aeedfffbe548a5
    .dword 0x8b3011282c9c55c5, 0x3306e5339dc36
    .dword 0x6a732c7c75ad536c, 0xa605a782e9cd6276
    .dword 0x4ede64eb24c733c8, 0xbf9cc32fe392ba16
    .dword 0x629b3dd55a1f36f1, 0x246ddebe79d643b9
    .dword 0x2793721f26cf541c, 0xc1df13b51b011e0e
    .dword 0xb7ee84e2fe90de2f, 0x39d8c05170a16a47
    .dword 0xd24f5ddd14543b9e, 0x413516c6179d3b53
    .dword 0x32dbe3524ef82edb, 0xf2e6996ad578f9dd
    .dword 0xf431e235a0dce501, 0x375787a931a9ce7f
    .dword 0xe22d52163d8bc83e, 0xf75c8499553835a1
    .dword 0xc06c529b8af32b, 0xf1bf4d8dbd27a6a4
    .dword 0x90f89cdfd28e8819, 0xd20d5458bc361c71
    .dword 0x68ef78202752a590, 0x9d26912ee8b059a5
    .dword 0x6480da5c8bca8ace, 0xcd91d6d609317fc3
    .dword 0xe57f44714242f041, 0xdeb5632e56fff78f
    .dword 0xbbeb46fb1eaffb43, 0x8c85d7b6c1153b6a
    .dword 0xe8ff1badb8147f6e, 0xa6004043c203c72d
    .dword 0x932966e46c66921b, 0x712aeb025e48166b
    .dword 0xd75276d0f420b704, 0xc889865dcfdc7fc6
    .dword 0x45488a0872aa3f21, 0x224d8f5b4ab4e091
    .dword 0x33c0d23d90d53b48, 0xd90b1275f2b1706a
    .dword 0xcf207f83d079d15c, 0x8d194f5f055f54d
    .dword 0x7cb64bca289f9bae, 0x4a8566b9166cfe7b
    .dword 0x9244366221b5774c, 0x6dee4599e1e4e3d2
    .dword 0x2eb7922b81cf559e, 0x2d243132e4301276
    .dword 0x5900cbb2493cc5e9, 0xe14fb2e24e8f3ab3
    .dword 0x70b3389cd4d6a441, 0x69b76b42c456fc88
    .dword 0x39e8cdb4596a3dbf, 0xb21f19167ebeb4a4
    .dword 0x4e28ac18b6a2a0ca, 0x2c7f4299c8ad2d9d
    .dword 0xad6490ae749e5719, 0xe677fbbb5108f45c
    .dword 0x9fbb591b6822f6ac, 0xb26062d3b7565c42
    .dword 0xfa37d53552f7ed49, 0xa1dc34d6e8b90a04
    .dword 0x8d9b72c15fe8a149, 0x67c3002a04995f17
    .dword 0x5f3b4e91f2312136, 0xb825fee09208b3f6
    .dword 0xad99102efee6470, 0x496d89b378f3d01c
    .dword 0xeaf837362be7e24b, 0xe23b68ca5cfc117a
    .dword 0x669cf55b64ce363, 0xea4a7e7d1b99038
    .dword 0x3ba3272d8d3346d9, 0xdee132de313f2603
    .dword 0xd8dc54c9a7a9919a, 0x628d4a11f504e52d
    .dword 0x3c0aa5148a5e5b30, 0xc155e7b11be460f3

    .align 12
data2:
    .dword 0x6df6a09118ddea4b, 0x1671eeccdb4f8da7
    .dword 0xb289506c4c7e91a9, 0xf42efd4658b3f984
    .dword 0x3a1bee5536e232e7, 0x3f1ec4d118e9cab7
    .dword 0xf19397603989f40a, 0x2e3f1e9d48357e92
    .dword 0x91525ad2f3303d9, 0x44eafb85b947baf2
    .dword 0x75a0e6ec46ea9135, 0xe7a5537a85443303
    .dword 0x308c662c5e2c87ce, 0x117b1233f6a9915b
    .dword 0x4a35446736fc120f, 0xcc27c5f0e386a12e
    .dword 0x47b42001915f3394, 0xc1a69deb6e39df28
    .dword 0xed8ac2fd6aceded9, 0x10fc3fe8b5ede000
    .dword 0x2b6924d14d4fbfc3, 0xfd5026d9ca7a4817
    .dword 0x608227b5027bd1c1, 0xf6ce7d2c7626f584
    .dword 0xa8e4a90bfd18ef4b, 0x66ce4cb6b2e7a5c1
    .dword 0x8ee91ac2a9bc15bb, 0x1346e4df2a138c67
    .dword 0x48adcdf5b4f42434, 0x6ff9f682e2b97f09
    .dword 0xe225a9f913b8a71a, 0xc554918add565e37
    .dword 0x56fc848f4d965684, 0xce989083a8e0e86e
    .dword 0x24bf4b6fdf04f5f5, 0xfec3355926212f2a
    .dword 0xa5e2ccfc18659b09, 0x5ef1fdf7c2153710
    .dword 0x299fb5650c574e59, 0x4e703bddd1638410
    .dword 0x73c4875287333f8d, 0x3332e8b025dba14b
    .dword 0x76690863b4867eb3, 0x44aad2aadec4adcb
    .dword 0xb8185f2ece190da9, 0xeb549a9aca42db0c
    .dword 0x24ba59d9471f5e3, 0x6f090befac2de8ec
    .dword 0x251704ae0ebd0bab, 0x28ce029453ad2bde
    .dword 0xe1291f23d93529b7, 0x8689a60a3f939a60
    .dword 0x6e153f9a1e5ba6fb, 0x9760bf5656f0ebc1
    .dword 0x2247df8e2d1cbf04, 0xe91b0d47d1944fe5
    .dword 0x404a170f9887d50, 0x144d35da401722a
    .dword 0xe843e1ec097c34be, 0x3eb461f55a0089b4
    .dword 0x937c266ba4b0d9d0, 0x82a50b7fcb3a8638
    .dword 0x6de70245d32838ec, 0xf756e91f457b5636
    .dword 0x3841f0f5bad66023, 0x55c00cc119b1292
    .dword 0x2016274275d02a44, 0x16442325a178370
    .dword 0x2321b698a9248432, 0x779c55ede2f2aed
    .dword 0x14bcf15d2608abd1, 0xec56abef6301901e
    .dword 0xd3b141a45bd930c9, 0x6083730ca004518
    .dword 0x8448607e2c686a77, 0xd52d79aec149406b
    .dword 0x397fd74d9820cd1f, 0xe696ac203764c508
    .dword 0xc9665207956f6070, 0x4e7a83e5e82a3ff9
    .dword 0x46c00d5192bc9028, 0xe5e1efa38a7ae0f2
    .dword 0x71a8b11257fda67b, 0x39598095ffc90661
    .dword 0x88b8b3b79487863e, 0x73f208be1d59585b
    .dword 0xb81186349cc430f0, 0xc30850a8fa4fa300
    .dword 0x462dab2fe3f81b8c, 0x378869e985d4bb97
    .dword 0x55d8b63d46489f50, 0x19411d633eb926ad
    .dword 0x6e0c020f8737c21b, 0x3a9a9c1557a1d60f
    .dword 0xc95d57f24a90ffed, 0xfbe0e2efb79105f5
    .dword 0xa81dd248f5b05b83, 0x3cb4630ff194099e
    .dword 0x5c13de11f3c6a1e2, 0x1a4d9da976b0ed72
    .dword 0xb45bd44a036987e1, 0xe2f9efc90b4dd52d
    .dword 0x7822e90fa581ec0d, 0x2b258631b9655824
    .dword 0xea1aaad83bc8b155, 0xf3e8b8fdb1c47ed1
    .dword 0xad94b9922d56101, 0xa7d6da78ae99dc7b
    .dword 0x506953fa15a87dac, 0x4fe724e9acaceefb
    .dword 0xb5d6f50edde085ac, 0x2eaaaebe91b6e82c
    .dword 0x89077eee1aeff61a, 0x1940cb6e166e0345
    .dword 0xcc9b3ab15faabdd0, 0xbd9cad8651d3ee30
    .dword 0xcd32338663c9079, 0xa901a4dfac24ea2
    .dword 0xcf1ff112fbb4f885, 0x8c2f758db8dbde77
    .dword 0x11d6067285ec6ded, 0x2eb2f7e162a13420
    .dword 0xabd5e761dd1a45d9, 0xb4ac83d8c42d49d2
    .dword 0x9281351fda7a717e, 0x1ddbadd385abb5cc
    .dword 0xaa6dcd776343545b, 0xe7d1e543ebb7afbc

    .align 12
data3:
    .dword 0xb632f373220abe5d, 0x84341685e9f11ef2
    .dword 0xc157f59684aad24c, 0x5b90d2628a62cc17
    .dword 0x315e5a7c6d88cae7, 0x84c4074da5dec087
    .dword 0xcc91b8c702f31b09, 0x1e145a1a699d17af
    .dword 0x7466b0b6913fbc52, 0x1424f027a18ada74
    .dword 0xf79cecfb2309eb04, 0x310ed5bd4419224d
    .dword 0xa8d54ff2c9e97f32, 0xffe1ed5ebafc6530
    .dword 0xa3fb28811e4dcc0, 0x1a76e07f772b46ae
    .dword 0x69e0da1c2f33e55f, 0x1338f252b7e58e9d
    .dword 0x89f3aa4a2220db8f, 0x32e03c4f8b5349c5
    .dword 0xeee9850276a6472b, 0xac22dd413026158f
    .dword 0x12cd7c70b8825a6c, 0x4373a9bc894e71a2
    .dword 0x1317ae311c362c29, 0x5186f89790be8ca2
    .dword 0x66b756e8c06e33ef, 0x8525910a82a45a75
    .dword 0xc82b8cc30f2182e1, 0x231911c4229faddf
    .dword 0x4e18284bac339dc0, 0x1f4fd9a53a33a600
    .dword 0xcdc2809420c3c1e1, 0x209a114f101453db
    .dword 0xb02d0a3e7443b2fb, 0xe9a077c1c33de330
    .dword 0xaa4607e149381a8d, 0x39b5151f569a86b7
    .dword 0x472b8e8fe50444a3, 0xe7d6ae2fb9191855
    .dword 0xb4894a75eceffb77, 0x1e372f471d6da8e3
    .dword 0xe02e9e755a1f8edb, 0xe6a8e6c938bff2bb
    .dword 0x8764dddab6dfbf81, 0xd1182967fece09eb
    .dword 0xc9ccbd041a33c864, 0xbf9c776eb73a8d2c
    .dword 0x1731c006afe98e57, 0xbfd2b57cccdd36ff
    .dword 0x9e27888a4cbd6f7f, 0xca29e4d33219b607
    .dword 0xc8bf72e6243dfa15, 0xa5c6430fccb0891e
    .dword 0x7b4537979dd140d2, 0x56b4a2a61c0ce1db
    .dword 0x9df193b3d31519eb, 0xb355add499f64436
    .dword 0x239dc58bb375b300, 0xd66a5fc89e21494c
    .dword 0x4c270229d7ac7938, 0xe1a9ca749c609675
    .dword 0x23a394b9f349c64d, 0xb5576f9ba11d340
    .dword 0x169a3536d7745697, 0xa3948cdcf7a321a1
    .dword 0xa8cb02757af79fe, 0xfa8f0fc3a59f8505
    .dword 0xe53086701820a295, 0x9b84d60ff683fafc
    .dword 0xb504651f22e93b27, 0x3b6bffe553a3369
    .dword 0xeca16e4adbfd14dd, 0xf4c87e1968d6d607
    .dword 0x818523219a8e360c, 0x5c2736e8f9d04157
    .dword 0x52167ce41b2f2c97, 0xa62e0e7522107b40
    .dword 0xcbf4ed17778179bf, 0x382a346abf96b02d
    .dword 0xff680dcfe059e87c, 0x4e8e227b046de061
    .dword 0xacefffa79677a510, 0x5053659facaed7ad
    .dword 0x6d8660c376e50bd4, 0x7e7f4e8280c82b0
    .dword 0xde10a1988dca1079, 0x5afa8adb5f83a9e
    .dword 0x4c21cf48ffd727ff, 0x261a98a26cc1c970
    .dword 0xc12fad58ad1dbd72, 0xc97a8744f2f8b8a2
    .dword 0xb4d3bbb345ffd6e2, 0xe608ec6792b9156d
    .dword 0x8c3f959e39979081, 0xe1db3aa702ee0fe5
    .dword 0x3b7dfed4b4b06eba, 0x9eef5d3058308b19
    .dword 0x41d77304e76f0f71, 0xce0e46f6f16c3e8
    .dword 0x4e10c8c745c84215, 0x751bf59d908ac081
    .dword 0x903d43c20b221313, 0x49694fbad7162f61
    .dword 0xb85c610df00ab394, 0xe342bb06a4ed9d93
    .dword 0x965654d062679a93, 0x318b030d5387bf41
    .dword 0x6124247fc1a1506d, 0xeedc11d4be072328
    .dword 0x2a3ecd4256273726, 0xed576ece82786156
    .dword 0x75621bcf43f0e268, 0x7e81dd1cfbcb787b
    .dword 0x1bffe5be0108fea9, 0xfdfaf6207e9a315
    .dword 0xb93e9d52a9702ab9, 0xc8175a3c6b164b0
    .dword 0x13456c205cfd6d52, 0x4a65b6907ec773af
    .dword 0x509e7a66da84d12a, 0xadbf21379981d04e
    .dword 0xca63f5f338f00dba, 0xb749c691b6026048
    .dword 0x68d661ea2c563ed7, 0x838966ce7690f08b
    .dword 0x35cbd6af00ebddd7, 0xa7fdc28709fccb74

    .align 12
data4:
    .dword 0xa71791c270274b4e, 0xde415fd0a91cf7a8
    .dword 0xb8acedfeadc09768, 0xb7f45d863951fbfb
    .dword 0x4f59c5d6478214f7, 0x359cd6730dca93f6
    .dword 0xcd88afb81efd9b43, 0xb4b2681d6b666e62
    .dword 0x4e91c031a21cb83f, 0x77c30f6f3d3fcfa7
    .dword 0x3bf4df66eee60a26, 0x55ecf47bf16e11fb
    .dword 0x61450fb7fe797e28, 0xa1c1cfb3f76591bb
    .dword 0x757e0f8493a6ee01, 0x554aa45e9a724fc1
    .dword 0xd8c4a80d45c7421b, 0x357995a69fcc9317
    .dword 0x48bd19db90e99703, 0x5aab1db5263b285b
    .dword 0xcf5117353ec7ee68, 0xa14b7c9ffc765e6a
    .dword 0xebf89ee4a81a59da, 0xf334893adb2bbde5
    .dword 0xafb0188517276f44, 0x90c3216c35ae31f
    .dword 0x264b178864687f43, 0x91861cd83afaa42a
    .dword 0x835c8f0b10632290, 0xb2957e7337269c75
    .dword 0xf170b9f2f176f6f8, 0xfcc8fbfcdd2e6c0d
    .dword 0x896e47042a6c53a4, 0xb5872acd0aa90409
    .dword 0x42965fecb27b8369, 0xc7becb0bd6c69ca4
    .dword 0xcbdf1d3244e0b4cb, 0xbfae99b7becb3833
    .dword 0x7cdc99158e60a097, 0x6d6364da68852693
    .dword 0xb714e511b3514efe, 0x60ca01a89d785a51
    .dword 0x7e81e9393945cb9e, 0xcada20c2c9a2b817
    .dword 0xbe5eaefa0533fade, 0x3de3e1f07598059d
    .dword 0xdbfabaebb2ead9e, 0xd4da4cf800e774f9
    .dword 0x3d0fbe31e41fddbf, 0xc0174ddc8b3c9857
    .dword 0x606ed872206db3f0, 0xb0832a0a19c41bdf
    .dword 0x5eb38b9e8cde058, 0xf47735a88eef08ae
    .dword 0xee2436685d9eb625, 0x2d64fb0729992393
    .dword 0x2c3a92ff7f022895, 0x8dad6ab9467fc852
    .dword 0xe77bf68bd1167e11, 0x218f69ecd212a6b5
    .dword 0x667c13f8401555e9, 0xfdbde621e60ed8ef
    .dword 0x2712281400fb5272, 0x949d139590f59e6a
    .dword 0xb7f0892b566037b9, 0x355b86cfd95aa416
    .dword 0x53eeb9a17b526f0d, 0x3e9c9ab9dfbb87d9
    .dword 0xebf82710a0b6b36e, 0x22f8d1b3d169966c
    .dword 0x62abc1a3bf8b045c, 0x6a19dd83401e7c68
    .dword 0x768c98af369b6dd, 0x2764e5c5bb19b77
    .dword 0xf01a25c20d6f7d39, 0x9888484a0a96febd
    .dword 0x5605c66bdd6c8583, 0x235d66ffad55cea5
    .dword 0x8bc33e285c976fde, 0xd18ac83a665a00b3
    .dword 0xb922c8501a96869c, 0xcf6b3cf8fcb48952
    .dword 0xd355b429e56a174d, 0xc41b0355df44dfa0
    .dword 0x87f569a8f4cc251f, 0xd01186e94a9d4444
    .dword 0xf0270c31bb17f57a, 0x64218f746691fdc2
    .dword 0x25946c7d58f31aa1, 0xae348826b5ae1ca2
    .dword 0x13f950fbb0a797bf, 0xf83895bd1acfb81
    .dword 0x88b7a1725b695227, 0xb84b6f8282c43e71
    .dword 0x5bd5eb7fc832e129, 0x3a9a3aad7768e462
    .dword 0x1b64e03a4e187b34, 0x6d7f5b2ed5c0370d
    .dword 0x21f626a2c1773f86, 0x845332d4cc4e9d54
    .dword 0x64685c728256382f, 0xa9ffeee7965930ec
    .dword 0x627f46032180780b, 0x88d8d1d28dd4fd3e
    .dword 0x2008ed2ffd3752fa, 0x744894de9108f79d
    .dword 0x30915ec125dc4b86, 0xfde74d37666b9951
    .dword 0xc1449e60bb649895, 0x7e890ca01eb33d8f
    .dword 0x7465e26858512ebd, 0xd84a50375a7c6408
    .dword 0xb8f900f3bf5f4440, 0x3d6b9617016b2423
    .dword 0xab7e5fdde5336812, 0x830b9d84a95b184
    .dword 0xa14745987e8b5533, 0xea409f708513107f
    .dword 0x167bfe7c45b41974, 0xbe420b72f6edd845
    .dword 0x5576a8753da5481e, 0xc0ecad4dc20d71ba
    .dword 0x6bfd0ccf1ccd0c50, 0xc93d64b0bbb0af7c
    .dword 0xd49b9de8755cce6a, 0xaf5897a8a5a52c73
    .dword 0x3013d7f5506ab5f6, 0xf3704dde4bf2e7c1

    .align 12
data5:
    .dword 0xa27125fe84404f62, 0xde35e9476e48f226
    .dword 0xd62e4998bba7940c, 0xd4a471bd7df51c17
    .dword 0xc3be7a501e45d9de, 0x113b7a00b6b43d7b
    .dword 0xbb8fa72f72916ca3, 0x4e792e6aafea164b
    .dword 0x5ff8497e545a9018, 0xfd61955894bcd2ae
    .dword 0x71821a0f187b3930, 0x2838a07c70eec2a4
    .dword 0x440687b3ade8f265, 0x11be192842bc9379
    .dword 0x9dab7b731dfeed1f, 0x5435f94d4d0ec1c1
    .dword 0xaaf1372fc8ea70a4, 0x5792eaa8bf3b04c4
    .dword 0xcf16416e85296694, 0x5d17a6660265c392
    .dword 0x1ccd934fe7719bfd, 0x24fc03771aa8ce4e
    .dword 0xfae25708115e7d8c, 0xa5aedf57713647f2
    .dword 0xb3a2612f2680621d, 0xb2cec224c88ee55c
    .dword 0x56c6648aa08c565b, 0x611304530ac5e0f2
    .dword 0x9345554e904eb2ff, 0x975f0e1300827ad8
    .dword 0x6cf1a510cc4df662, 0x600e63014895d43
    .dword 0x290023c490e83317, 0x48deadfe5a1be006
    .dword 0xfb541d7fa75fc527, 0xabc1371c6bb71347
    .dword 0x544b82f3fb832063, 0x123fd7d89bf85320
    .dword 0xe60d255ef386ea97, 0x1889737418262f40
    .dword 0xd6ca55f38345d2c, 0xab09d8b80b8b2841
    .dword 0xb2f9099e40deca39, 0xd55df1f435dac9
    .dword 0xb52ef2a2ee5feb56, 0x3683445ef599a0e
    .dword 0x9691ecac8cf0f6ed, 0x6c1bee6d4bcf52e5
    .dword 0x6760e9cfce33b33b, 0x1bf5a717619efaac
    .dword 0x3cd060460531d2cb, 0xfc17bc64ded4c984
    .dword 0xf19ce1e6efadf389, 0x5f0118b21b680c8e
    .dword 0xdd4d1555453c49f8, 0xa469a498aeeb4072
    .dword 0xa48625e15e495e5, 0x907e4dee0f14625c
    .dword 0x501bfc0d5a17822b, 0xe6bcaa99459d81ae
    .dword 0xeea644a16616a634, 0xb3418a9593966a8e
    .dword 0x89af067b07e3a87e, 0x469d9648cc2c4e92
    .dword 0x19b59e714d7893ee, 0xac8a90044d3e06b4
    .dword 0xa157bd1e3a5fc812, 0x1a2223745b56e496
    .dword 0x2c957d0899afab9, 0x2a1395edd8dfff42
    .dword 0xd7293d0b1a0459d8, 0x9b47752ed798e3dc
    .dword 0x31252be98988d830, 0x2e93ea3523537479
    .dword 0x7ccfc1f76312e1fa, 0xa7142e456d9f9b94
    .dword 0xba8d4f9b455c17f1, 0x3f7d198fc8f8f75a
    .dword 0xbf9967ba304454df, 0x7107631ed3041bd1
    .dword 0xe91d20cd6ac1ac2d, 0x81e8e2c20d4b3ff2
    .dword 0x93cef58fb7d406b1, 0x85d38424dce612bb
    .dword 0x53746dfba3c4063c, 0x65ef7accc8c67d1f
    .dword 0x47f2e59193be5c6, 0x5887121a7c5dc1f4
    .dword 0x28371701fee71390, 0x79bc8d68d295a3ed
    .dword 0x2a08bac2684a10fe, 0xacc5f5b481784b78
    .dword 0x168173a690586f2c, 0xddf58819361748b0
    .dword 0x4fb7fc8f48509bde, 0xc3d8620bc82802fe
    .dword 0x90eb22cce9d01a28, 0xb960f5fa33775924
    .dword 0x53e8ec6d1d3723d4, 0xb837807e2417af1e
    .dword 0x3ab90573d12cf30, 0x96456d0634b3148d
    .dword 0xaf5516b249c2d20c, 0x7c5f2fa8b8e7f2fa
    .dword 0x17879852d659de6d, 0xae88b57cb4efb5c
    .dword 0x9ce324352db17492, 0x9a7915d3f61b2636
    .dword 0x8bacd8a02afed0f1, 0x60d7521ecf96c6f2
    .dword 0xa05e6f7e2e2e5925, 0xd8549f1b4b567e08
    .dword 0x7ad3b8f788155bd0, 0x2802bad947f5177b
    .dword 0x151dd2487768c9de, 0xa61959241768f812
    .dword 0x57ccc73935b0415a, 0xd19335745fb50a0e
    .dword 0xe9ffd5bff5f635cc, 0x53446c9b582c71f9
    .dword 0x4d4bc3533023269b, 0x207ff214889160cd
    .dword 0x8af6af6511355a42, 0x8528fc4b614b107a
    .dword 0x2668c55a9660bddc, 0x914c4e2f7159f171
    .dword 0xf79a4387ad7d8751, 0xea3f23d9624bb1a4

    .align 12
data6:
    .dword 0xfa33de57bee96b13, 0x69ae8f5b08c37efd
    .dword 0x8b10afb5ea39268, 0x875960df17511961
    .dword 0x50cc5c5f445830a7, 0x6a37a4e87fe18004
    .dword 0x70ea7469a9b12c50, 0x4bb769ba3f9c18c4
    .dword 0xa6098b6c1c7f852, 0xc746930b693b7914
    .dword 0x7d07bf9fd5219c3c, 0xea82232e10b43e81
    .dword 0xfa767d49d85b0368, 0xd0f240edcf849f7
    .dword 0x440a73fbb69bba4b, 0xdd21f3b166eeadce
    .dword 0x150c444d93a88def, 0x237a7c80a70637c6
    .dword 0x1ace38c7efd46c9f, 0x81df1df29770c239
    .dword 0xe2001bbab751d7, 0x3304b247d7a15c07
    .dword 0xdb41c3dd32a00e76, 0xdb545dd40be15b82
    .dword 0x61e8f8f030fe62c0, 0xec9d51375fbf9ce6
    .dword 0xbb2a75f8dee37362, 0x23b415f9e60ea54b
    .dword 0x645ed6c804d2d057, 0x5974ca32327af7f3
    .dword 0xac8046a235338ced, 0xad9169d959cd99dd
    .dword 0xce0dedc998c5aff2, 0x1afae685386b5827
    .dword 0x95adec418c92d50e, 0xdc4cfd7dc42ba0ce
    .dword 0x797678547500b3fe, 0xaeba44b175a9d9bc
    .dword 0xdb4df8505822d9, 0x678298370ed09dc3
    .dword 0x5c17995401d5bfb7, 0x4ab8bc520eb2713
    .dword 0x44b8923df23de763, 0x8252b283826dce65
    .dword 0x26e87593fa8727c5, 0xdf7081beed1c5b8
    .dword 0x7e4fdc9a1e358997, 0x1334e6c5ffa8c216
    .dword 0xc435cfd829d74cbf, 0x4916eb6d3662c247
    .dword 0x7ef8869a4dc13c04, 0x955cc6c027020730
    .dword 0xf507a6e238a5b57f, 0x63d60771634ce59a
    .dword 0x3903e2796a5ec1a5, 0xfb6b1ad3b6edece6
    .dword 0xda862b0578bf8a86, 0x85ed9c8efd92ed62
    .dword 0x96d33834275bf006, 0xa238e90c43720ef3
    .dword 0xdec51d913cf53678, 0x60128d45924ecb51
    .dword 0x67e5039ca4833244, 0xef0019a0a6578194
    .dword 0xf34164201c6f35f5, 0xb8d21572ab432f52
    .dword 0xbaf58152cfa5a4f3, 0x16cc07626a0e0991
    .dword 0xd476279b67c5eae7, 0xd4e9a3bc4be8a75d
    .dword 0xef26d73d9b3a1bd6, 0xbcf857cb2a00d9f9
    .dword 0x64f63eac727599e2, 0xe7b03b1aa2354553
    .dword 0x6109ec13796acbc8, 0x3b4843c92dd86932
    .dword 0x7703b7b7f711902e, 0xd35ce385d0f8c957
    .dword 0x79d8db0361f44177, 0x70d120000f1a2a0
    .dword 0x8ac0b8b11482f337, 0xdf2a91546903a33b
    .dword 0x483e984a8896b3c8, 0x27279655c379f821
    .dword 0xdf3bd8350b1d7356, 0x3fd5aebef0f6bc0f
    .dword 0x66eba1ddc27dc790, 0xe41108d3bf6060d8
    .dword 0xacb5e0fe4d425850, 0x11687cde100e1d64
    .dword 0x52155c3f56ba9a10, 0x95b1aad8d7aec486
    .dword 0x6142e0c91f8cf6e1, 0x6178c2367871e270
    .dword 0x78a92e317c83cac4, 0x4e8b29b730fa5090
    .dword 0xfd7bd570b2d93dec, 0xb2af623352a704ee
    .dword 0x3855fef2b173758d, 0xc012fdd71ea3b2d8
    .dword 0x6579e1d5a995abca, 0x8d4f311cb6a60835
    .dword 0x69d36046294877bf, 0x9f58602746c270ad
    .dword 0xe06108cb0b63c8a9, 0x485f388c78310bfa
    .dword 0x7e6e09683a001f1b, 0x83afc68c5aeff65f
    .dword 0x62881b1bbe57182c, 0x16a249b7e3abfb04
    .dword 0x5e40e3049f3ee01b, 0x6bab37e24e39888a
    .dword 0x75a3e3301843c2e9, 0x9cd53b163b676f10
    .dword 0xd599c8c9f76f5ade, 0xffa33a216a3545bb
    .dword 0xdc8ce64c197d399d, 0x4fdaff87b25ce87d
    .dword 0xaaedc673224b2397, 0x7067f9e7a4bda46
    .dword 0x1d1ff9d556bfa845, 0x6b75499393227f65
    .dword 0xca271233a45f0251, 0xdd10645fd4febca7
    .dword 0x4c435d2811b56ea5, 0x1df1aab91ed65c9b
    .dword 0x62d95d0185732966, 0xcf895127facefaa0

    .align 12
data7:
    .dword 0xca8875bdf995f8f8, 0xf467541e7990dea6
    .dword 0x7b30a398675c9850, 0xfef6d78c0b4455c3
    .dword 0x60b2a4da4629865f, 0x72355006e1e7c10a
    .dword 0xa9e1e18b63e0bcae, 0xdb48c6762dad7c29
    .dword 0xd59ac7812a12647c, 0xc315218157fe7ca4
    .dword 0x2dd5264beb6b6e6f, 0xc21bfaf87e7f0b42
    .dword 0xac159557113f3538, 0x62d470adedc572be
    .dword 0x51b76b6620b5794f, 0xf78e6089986131e1
    .dword 0xc6df746fbb3eecbc, 0xa83a79990ca3c6c7
    .dword 0x5229f5296d8e2fae, 0x1d16b222490bd08e
    .dword 0x4463e120dc0dd317, 0xf5c3297f3dd8d59e
    .dword 0x9281fb82cc877e09, 0x530d5479fbebb624
    .dword 0x4107b6622238e7bf, 0x4ad5c2f41db1ea04
    .dword 0xd1e43a3a7a044ac4, 0xac9c870071c1c1d3
    .dword 0x10ca5453f36e7cfe, 0xdd76d0f406798922
    .dword 0x640847b9d36f57de, 0x161c69811936cc0f
    .dword 0x5cca605d1cb9f4af, 0x89febea437f43f6c
    .dword 0x682bebd6158846f6, 0x997aaf7af76e73b7
    .dword 0x6b276cdb05c36755, 0xea7e530ce79f3309
    .dword 0x461779455cc8489d, 0x99e574455d9dcc2c
    .dword 0xdc9422d21e783e4, 0x3f031d0a7f58e4f2
    .dword 0x9bbacec6d3da76e6, 0xacbbf55f1d9b173a
    .dword 0x7516e0fb0fc73202, 0x2b848e42153838f1
    .dword 0x40722e136d745663, 0x8e039c059b440cd3
    .dword 0x7790067e9be60b1a, 0x56994b69fd84e7a7
    .dword 0xdaba7d183a5cd8ea, 0x8bdc416a55d10656
    .dword 0x785b44ccff61f7bf, 0x6da014715a9c9a7f
    .dword 0xce73b27dc3d9362f, 0x85f628bd28966472
    .dword 0x42721c29fa2010c5, 0x7d6b8300e264c4df
    .dword 0xeaeae751ce38ddaa, 0x77b65420e9e445ae
    .dword 0xf98e4c56a6c20c59, 0x4893edcf03557649
    .dword 0xf5b8994f080bcda5, 0xfeb7fa923d75319e
    .dword 0xd8034aebc9eb4ec1, 0x7f2ca1d20927f797
    .dword 0x97ec21df49e472b9, 0x611427a1b491c442
    .dword 0xc10227ddfdddaf2f, 0xf44ea3117a4566b7
    .dword 0xe4822bf8e4ae0802, 0x1f44c27b95dbfa71
    .dword 0xb004a5945ecb06b5, 0xd6c0c3563843ee04
    .dword 0x7f2d7aeb632a318, 0xf67202d882dcd78
    .dword 0x506de58c6a904df9, 0xc0d71bb5f8991304
    .dword 0xf37bd86464ca34c4, 0x4801b4a8125508c0
    .dword 0x18bb0e3ec9141997, 0xf049670fdd4be3c4
    .dword 0xd90de8ef57c6cd0b, 0x155a558b45af470d
    .dword 0x8652c2854fa8888, 0x489e7eec60b850a7
    .dword 0x75e859be389fa45b, 0x57d57ad39f052e46
    .dword 0x7b0ee475c993d9e7, 0xc23d2f92aa05a4e3
    .dword 0xa0bc6cbf26498a80, 0x9002f0d75d0e71af
    .dword 0xde4496d90ef030ce, 0xc6107e20446ea9b5
    .dword 0xf079bf53987bf409, 0x6e0c0fa1d1bc12ff
    .dword 0x99a6a253c6b7016d, 0xc6bf47645af4199a
    .dword 0xde09d2874693fde3, 0x18dcd53535a76ad2
    .dword 0xa649fa346925a577, 0x3adf83e52ece7dfd
    .dword 0x9984671fb47465db, 0x444e81a8f2f11445
    .dword 0x9019fdf7b938e29, 0xec13adb92c53004f
    .dword 0x27738c8309f727d3, 0x997efe122a447ad
    .dword 0xa0decf9365e038c, 0x553cefbc93f3a044
    .dword 0xa612d1f635483cd6, 0x14a85abdbdcaeb9e
    .dword 0xe72026e544f10bf9, 0xc4edd885f5863c07
    .dword 0x4295db83450df32e, 0xaeb5f69015330054
    .dword 0xc71f7c3644c29f5b, 0xd44d6ece5234cdf6
    .dword 0x28e1ca23941f79f6, 0x1015e33b330d41af
    .dword 0xd76e5ad5c81f83b, 0x4944abbabdaf7311
    .dword 0xfd103cf82f6187d6, 0x5996c97369f9968e
    .dword 0xf710d20fb69b9c40, 0x51f14b30573e5086
    .dword 0xf3fcdb08818bbf37, 0xce1fffcaed14e200


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
