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
                    la x21, data1                             
                    add x19, x19, x21                         
                    fld f0, 0(x19)                            
pfx.bb0.l1:         andi x21, x21, 0x3f8                      
                    la x19, data0                             
                    add x21, x21, x19                         
                    fld f1, 8(x21)                            
pfx.bb0.l2:         andi x22, x22, 0x3f8                      
                    la x19, data4                             
                    add x22, x22, x19                         
                    fld f2, 24(x22)                           
pfx.bb0.l3:         andi x18, x18, 0x3f8                      
                    la x22, data1                             
                    add x18, x18, x22                         
                    fld f3, 8(x18)                            
pfx.bb0.l4:         andi x20, x20, 0x3f8                      
                    la x18, data7                             
                    add x20, x20, x18                         
                    fld f4, 16(x20)                           
pfx.bb0.l5:         andi x19, x19, 0x3f8                      
                    la x21, data0                             
                    add x19, x19, x21                         
                    fld f5, 8(x19)                            
pfx.bb0.l6:         andi x22, x22, 0x3f8                      
                    la x18, data0                             
                    add x22, x22, x18                         
                    fld f6, 24(x22)                           
pfx.bb0.l7:         andi x22, x22, 0x3f8                      
                    la x18, data2                             
                    add x22, x22, x18                         
                    fld f7, 24(x22)                           
pfx.bb0.l8:         andi x21, x21, 0x3f8                      
                    la x18, data3                             
                    add x21, x21, x18                         
                    fld f8, 16(x21)                           
pfx.bb0.l9:         andi x21, x21, 0x3f8                      
                    la x18, data7                             
                    add x21, x21, x18                         
                    fld f9, 16(x21)                           
pfx.bb0.l10:        addi x18, zero, 1754                      
pfx.bb0.l11:        addi x19, zero, 1717                      
pfx.bb0.l12:        addi x20, zero, 1681                      
pfx.bb0.l13:        addi x21, zero, 1889                      
pfx.bb0.l14:        addi x22, zero, 589                       
pfx.bb0.l15:        addi x23, zero, 357                       
pfx.bb0.l16:        addi x24, zero, 1892                      
pfx.bb0.l17:        addi x25, zero, 1564                      
pfx.bb0.l18:        addi x26, zero, 1180                      
pfx.bb0.l19:        addi x27, zero, 836                       
pfx.bb1:
pfx.bb1.l0:         addi a0, zero, 44                         
pfx.bb1.l1:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 8(a0)                              
pfx.bb1.l2:         addi a0, zero, 1345                       
pfx.bb1.l3:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 16(a0)                             
pfx.bb1.l4:         addi a0, zero, 18                         
pfx.bb1.l5:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 24(a0)                             
pfx.bb1.l6:         addi a0, zero, 158                        
pfx.bb1.l7:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l8:         addi a0, zero, 1220                       
pfx.bb1.l9:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 24(a0)                             
pfx.bb1.l10:        addi a0, zero, 478                        
pfx.bb1.l11:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 8(a0)                              
pfx.bb1.l12:        addi a0, zero, 1070                       
pfx.bb1.l13:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 24(a0)                             
pfx.bb1.l14:        addi a0, zero, 1980                       
pfx.bb1.l15:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l16:        addi x0, zero, 0                          
pfx.bb1.l17:        addi x1, zero, 0                          
pfx.bb1.l18:        addi x2, zero, 0                          
pfx.bb1.l19:        addi x3, zero, 0                          
pfx.bb1.l20:        addi x4, zero, 0                          
pfx.bb1.l21:        addi x5, zero, 0                          
pfx.bb1.l22:        addi x6, zero, 0                          
pfx.bb1.l23:        addi x7, zero, 0                          
pfx.bb1.l24:        addi x8, zero, 0                          
pfx.bb1.l25:        addi x9, zero, 0                          
pfx.bb1.l26:        addi x10, zero, 0                         
pfx.bb1.l27:        addi x11, zero, 0                         
pfx.bb1.l28:        addi x12, zero, 0                         
pfx.bb1.l29:        addi x13, zero, 0                         
pfx.bb1.l30:        addi x14, zero, 0                         
pfx.bb1.l31:        addi x15, zero, 0                         
pfx.bb1.l32:        addi x0, zero, 0                          
pfx.bb1.l33:        addi x1, zero, 0                          
pfx.bb1.l34:        addi x2, zero, 0                          
pfx.bb1.l35:        addi x3, zero, 0                          
pfx.bb1.l36:        addi x4, zero, 0                          
pfx.bb1.l37:        addi x5, zero, 0                          
pfx.bb1.l38:        addi x6, zero, 0                          
pfx.bb1.l39:        addi x7, zero, 0                          
pfx.bb1.l40:        addi x8, zero, 0                          
pfx.bb1.l41:        addi x9, zero, 0                          
pfx.bb1.l42:        addi x10, zero, 0                         
pfx.bb1.l43:        addi x11, zero, 0                         
pfx.bb1.l44:        addi x12, zero, 0                         
pfx.bb1.l45:        addi x13, zero, 0                         
pfx.bb1.l46:        addi x14, zero, 0                         
pfx.bb1.l47:        addi x15, zero, 0                         
pfx.bb1.l48:        addi x0, zero, 0                          
pfx.bb1.l49:        addi x1, zero, 0                          
pfx.bb1.l50:        addi x2, zero, 0                          
pfx.bb1.l51:        addi x3, zero, 0                          
pfx.bb1.l52:        addi x4, zero, 0                          
pfx.bb1.l53:        addi x5, zero, 0                          
pfx.bb1.l54:        addi x6, zero, 0                          
pfx.bb1.l55:        addi x7, zero, 0                          
pfx.bb1.l56:        addi x8, zero, 0                          
pfx.bb1.l57:        addi x9, zero, 0                          
pfx.bb1.l58:        addi x10, zero, 0                         
pfx.bb1.l59:        addi x11, zero, 0                         
pfx.bb1.l60:        addi x12, zero, 0                         
pfx.bb1.l61:        addi x13, zero, 0                         
pfx.bb1.l62:        addi x14, zero, 0                         
pfx.bb1.l63:        addi x15, zero, 0                         
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
prp0.entry.l0:      fmv.x.d x22, f0                           
prp0.entry.l1:      fmin.s f4, f0, f1                         
prp0.entry.l2:      fence                                     
prp0.entry.l3:      fcvt.s.lu f2, x22                         
prp0.entry.l4:      fsgnjn.d f0, f3, f1                       
prp0.entry.l5:      divuw x20, x18, x21                       
prp0.entry.l6:      fmin.s f4, f3, f0                         
prp0.entry.l7:      bltu x20, x19, prp0.bb1                   
prp0.bb0:
prp0.bb0.l0:        call fn0                                  
prp0.bb0.l1:        rem x20, x18, x19                         
prp0.bb0.l2:        call fn1                                  
prp0.bb0.l3:        lui x20, 3244                             
prp0.bb0.l4:        fnmsub.d f1, f3, f4, f2, rtz              
prp0.bb0.l5:        srli x21, x18, 4                          
prp0.bb0.l6:        fsgnj.d f2, f4, f3                        
prp0.bb0.l7:        call fn0                                  
prp0.bb0.l8:        auipc x20, 273                            
prp0.bb0.l9:        srl x21, x19, x22                         
prp0.bb0.l10:       jal x18, prp0.bb3                         
prp0.bb1:
prp0.bb1.l0:        fnmadd.d f1, f4, f3, f2, rup              
prp0.bb1.l1:        call fn0                                  
prp0.bb1.l2:        call fn3                                  
prp0.bb1.l3:        fmv.d.x f1, x20                           
prp0.bb1.l4:        fmax.d f3, f1, f0                         
prp0.bb1.l5:        blt x20, x18, prp0.bb2                    
prp0.bb2:
prp0.bb2.l0:        fadd.s f0, f1, f4, rmm                    
prp0.bb2.l1:        fle.s x20, f2, f3                         
prp0.bb2.l2:        call fn1                                  
prp0.bb2.l3:        and x22, x18, x21                         
prp0.bb2.l4:        fcvt.d.w f4, x21                          
prp0.bb2.l5:        fadd.s f4, f0, f3, rmm                    
prp0.bb2.l6:        sltiu x20, x22, 2012                      
prp0.bb2.l7:        fcvt.d.wu f3, x18                         
prp0.bb2.l8:        bge x21, x19, prp0.bb4                    
prp0.bb2.l9:        jal x18, prp0.bb3                         
prp0.bb3:
prp0.bb3.l0:        sltiu x19, x20, 1036                      
prp0.bb3.l1:        call fn2                                  
prp0.bb3.l2:        sraiw x19, x18, 23                        
prp0.bb3.l3:        srliw x22, x21, 8                         
prp0.bb3.l4:        mulhsu x20, x19, x21                      
prp0.bb3.l5:        xori x20, x22, 1903                       
prp0.bb3.l6:        srai x22, x18, 33                         
prp0.bb3.l7:        fcvt.wu.d x19, f4                         
prp0.bb3.l8:        srl x21, x19, x18                         
prp0.bb3.l9:        slti x20, x19, 1520                       
prp0.bb3.l10:       bgeu x18, x21, prp0.exit                  
prp0.bb4:
prp0.bb4.l0:        rem x22, x19, x21                         
prp0.bb4.l1:        sraiw x22, x20, 24                        
prp0.bb4.l2:        fcvt.s.lu f4, x19                         
prp0.bb4.l3:        fnmadd.d f0, f3, f4, f2, dyn              
prp0.bb4.l4:        sltu x20, x21, x19                        
prp0.bb4.l5:        call fn3                                  
prp0.bb4.l6:        fnmsub.d f0, f1, f4, f3, dyn              
prp0.bb4.l7:        fcvt.w.d x22, f1                          
prp0.bb4.l8:        mulhu x18, x20, x21                       
prp0.bb4.l9:        fadd.s f0, f4, f1, rmm                    
prp0.bb4.l10:       blt x21, x22, prp0.exit                   
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      fcvt.wu.d x18, f4                         
prp1.entry.l1:      fcvt.l.d x19, f1                          
prp1.entry.l2:      flt.d x21, f0, f3                         
prp1.entry.l3:      feq.s x22, f2, f1                         
prp1.entry.l4:      fcvt.w.d x20, f3                          
prp1.entry.l5:      divuw x20, x22, x18                       
prp1.entry.l6:      la x19, prp1.bb0                          
                    jalr x18, 0(x19)                          
prp1.bb0:
prp1.bb0.l0:        lui x20, 2635                             
prp1.bb0.l1:        rem x21, x20, x18                         
prp1.bb0.l2:        slli x21, x18, 13                         
prp1.bb0.l3:        fmul.s f1, f2, f0, dyn                    
prp1.bb0.l4:        slli x19, x20, 25                         
prp1.bb0.l5:        bltu x21, x19, prp1.bb3                   
prp1.bb1:
prp1.bb1.l0:        fcvt.d.l f4, x20                          
prp1.bb1.l1:        srli x21, x19, 16                         
prp1.bb1.l2:        bgeu x20, x19, prp1.bb3                   
prp1.bb1.l3:        fcvt.wu.s x19, f2                         
prp1.bb1.l4:        bge x22, x20, prp1.bb2                    
prp1.bb1.l5:        fclass.d x22, f2                          
prp1.bb1.l6:        call fn4                                  
prp1.bb1.l7:        srliw x20, x21, 22                        
prp1.bb1.l8:        blt x22, x21, prp1.bb2                    
prp1.bb2:
prp1.bb2.l0:        call fn1                                  
prp1.bb2.l1:        mulhsu x21, x19, x22                      
prp1.bb2.l2:        fsgnjn.d f2, f0, f4                       
prp1.bb2.l3:        call fn2                                  
prp1.bb2.l4:        feq.d x18, f2, f0                         
prp1.bb2.l5:        la x18, prp1.bb4                          
                    jalr x20, 0(x18)                          
prp1.bb3:
prp1.bb3.l0:        slti x18, x19, 96                         
prp1.bb3.l1:        fcvt.w.d x20, f3                          
prp1.bb3.l2:        rem x22, x18, x19                         
prp1.bb3.l3:        call fn4                                  
prp1.bb3.l4:        fmv.x.w x20, f4                           
prp1.bb3.l5:        call fn1                                  
prp1.bb3.l6:        divw x21, x20, x18                        
prp1.bb3.l7:        bne x21, x19, prp1.exit                   
prp1.bb3.l8:        remuw x22, x18, x20                       
prp1.bb3.l9:        jal x21, prp1.exit                        
prp1.bb3.l10:       bge x22, x19, prp1.bb4                    
prp1.bb4:
prp1.bb4.l0:        feq.d x21, f2, f3                         
prp1.bb4.l1:        bne x20, x19, prp1.exit                   
prp1.bb4.l2:        fmsub.d f4, f2, f0, f1, rne               
prp1.bb4.l3:        xor x20, x18, x22                         
prp1.bb4.l4:        fcvt.s.d f4, f4                           
prp1.bb4.l5:        fsgnj.d f2, f3, f0                        
prp1.bb4.l6:        xor x21, x20, x18                         
prp1.bb4.l7:        mulw x22, x20, x19                        
prp1.bb4.l8:        bge x20, x22, prp1.exit                   
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        call fn4                                  
tc.entry.l1:        sra x20, x18, x21                         
tc.entry.l2:        andi x22, x22, 0x3f8                      
                    la x18, data2                             
                    add x22, x22, x18                         
                    amoswap.w x20, x19, (x22)                 
tc.entry.l3:        fnmadd.d f0, f3, f4, f2, rne              
tc.entry.l4:        fcvt.w.s x19, f1                          
tc.entry.l5:        bgeu x19, x18, tc.bb4                     
tc.entry.l6:        jal x22, tc.bb0                           
tc.bb0:
tc.bb0.l0:          fence                                     
tc.bb0.l1:          slti x21, x20, 1319                       
tc.bb0.l2:          flt.s x22, f2, f4                         
tc.bb0.l3:          mulhu x22, x21, x19                       
tc.bb0.l4:          remw x20, x21, x19                        
tc.bb0.l5:          call fn1                                  
tc.bb0.l6:          andi x21, x21, 0x3f8                      
                    la x19, data7                             
                    add x21, x21, x19                         
                    amomaxu.d x20, x18, (x21)                 
tc.bb0.l7:          fsqrt.d f0, f2, rne                       
tc.bb0.l8:          blt x21, x19, tc.exit                     
tc.bb1:
tc.bb1.l0:          fmv.x.w x20, f4                           
tc.bb1.l1:          sub x21, x22, x20                         
tc.bb1.l2:          fmsub.d f3, f4, f2, f1, rne               
tc.bb1.l3:          fmin.d f1, f2, f3                         
tc.bb1.l4:          slliw x18, x19, 23                        
tc.bb1.l5:          andi x20, x20, 0x3f8                      
                    la x18, data5                             
                    add x20, x20, x18                         
                    amoswap.w x19, x21, (x20)                 
tc.bb1.l6:          divu x22, x21, x19                        
tc.bb1.l7:          divu x19, x20, x22                        
tc.bb1.l8:          addi x21, x20, 2010                       
tc.bb1.l9:          bgeu x22, x19, tc.bb2                     
tc.bb2:
tc.bb2.l0:          andi x18, x18, 0x3f8                      
                    la x22, data6                             
                    add x18, x18, x22                         
                    sc.w x19, x20, (x18)                      
tc.bb2.l1:          andi x20, x20, 0x3f8                      
                    la x22, data3                             
                    add x20, x20, x22                         
                    sd x18, 8(x20)                            
tc.bb2.l2:          andi x20, x20, 0x3f8                      
                    la x22, data2                             
                    add x20, x20, x22                         
                    sd x19, 16(x20)                           
tc.bb2.l3:          sltiu x21, x19, 656                       
tc.bb2.l4:          andi x22, x22, 0x3f8                      
                    la x18, data0                             
                    add x22, x22, x18                         
                    lbu x21, 10(x22)                          
tc.bb2.l5:          bgeu x21, x20, tc.bb3                     
                    spdoc_check_c
tc.bb2.l6:          rem x18, x22, x20                         
tc.bb2.l7:          fclass.d x21, f4                          
tc.bb2.l8:          slliw x21, x20, 30                        
tc.bb2.l9:          srli x19, x22, 19                         
tc.bb2.l10:         bne x21, x20, tc.bb3                      
tc.bb3:
tc.bb3.l0:          call fn1                                  
transient:
tsx:
tsx.entry:
tsx.entry.l0:       andi x25, x25, 0x3f8                      
                    la x27, secret                            
                    add x25, x25, x27                         
                    lhu x24, 30(x25)                          
tsx.entry.l1:       mulw x26, x27, x24                        
tsx.entry.l2:       remw x25, x23, x26                        
tsx.entry.l3:       fcvt.wu.d x24, f8                         
tsx.entry.l4:       fnmsub.s f8, f6, f5, f9, rtz              
tsx.entry.l5:       jal x25, tsx.bb3                          
tsx.bb0:
tsx.bb0.l0:         andi x26, x26, 0x3f8                      
                    la x23, data4                             
                    add x26, x26, x23                         
                    amoswap.w x27, x25, (x26)                 
tsx.bb0.l1:         fmsub.d f6, f7, f5, f8, dyn               
tsx.bb0.l2:         fmadd.s f5, f8, f6, f9, rdn               
tsx.bb0.l3:         fsgnjx.d f9, f7, f6                       
tsx.bb0.l4:         slt x24, x23, x26                         
tsx.bb0.l5:         fsgnjn.d f8, f7, f6                       
tsx.bb0.l6:         la x27, tsx.bb3                           
                    jalr x25, 0(x27)                          
tsx.bb0.l7:         fcvt.wu.s x27, f7                         
tsx.bb0.l8:         andi x26, x26, 0x3f8                      
                    la x23, secret                            
                    add x26, x26, x23                         
                    amoswap.d x27, x25, (x26)                 
tsx.bb0.l9:         andi x26, x26, 0x3f8                      
                    la x24, data0                             
                    add x26, x26, x24                         
                    amomax.d x27, x23, (x26)                  
tsx.bb0.l10:        blt x26, x27, tsx.bb1                     
tsx.bb1:
tsx.bb1.l0:         fdiv.d f9, f5, f6, rmm                    
tsx.bb1.l1:         fcvt.s.l f9, x26                          
tsx.bb1.l2:         andi x24, x24, 0x3f8                      
                    la x23, data1                             
                    add x24, x24, x23                         
                    amoor.w x26, x25, (x24)                   
tsx.bb1.l3:         fmv.w.x f5, x24                           
tsx.bb1.l4:         srl x24, x25, x23                         
tsx.bb1.l5:         feq.s x26, f5, f8                         
tsx.bb1.l6:         fmv.d.x f7, x24                           
tsx.bb1.l7:         andi x26, x26, 0x3f8                      
                    la x27, data7                             
                    add x26, x26, x27                         
                    amoor.w x23, x24, (x26)                   
tsx.bb1.l8:         fmv.x.w x27, f5                           
tsx.bb1.l9:         mulh x26, x24, x25                        
tsx.bb1.l10:        bge x24, x25, tsx.bb2                     
tsx.bb2:
tsx.bb2.l0:         andi x27, x27, 0x3f8                      
                    la x23, data5                             
                    add x27, x27, x23                         
                    amoswap.d x25, x24, (x27)                 
tsx.bb2.l1:         fcvt.w.s x27, f5                          
tsx.bb2.l2:         srliw x25, x24, 24                        
tsx.bb2.l3:         fcvt.w.s x27, f7                          
tsx.bb2.l4:         la x24, tsx.exit                          
                    jalr x26, 0(x24)                          
tsx.bb2.l5:         bne x23, x26, tsx.bb3                     
tsx.bb3:
tsx.bb3.l0:         addi x25, x23, 1071                       
tsx.bb3.l1:         feq.s x27, f9, f8                         
tsx.bb3.l2:         fnmadd.s f6, f7, f9, f5, dyn              
tsx.bb3.l3:         fmax.d f7, f9, f5                         
tsx.bb3.l4:         call fn4                                  
tsx.bb3.l5:         flt.d x27, f6, f7                         
tsx.bb3.l6:         la x26, tsx.exit                          
                    jalr x23, 0(x26)                          
tsx.exit:
transient_end:
tc.bb3.l1:          andi x21, x21, 0x3f8                      
                    la x18, data4                             
                    add x21, x21, x18                         
                    amomaxu.d x20, x19, (x21)                 
tc.bb3.l2:          andi x21, x21, 0x3f8                      
                    la x20, data2                             
                    add x21, x21, x20                         
                    lb x22, 7(x21)                            
tc.bb3.l3:          srai x22, x21, 33                         
tc.bb3.l4:          andi x22, x22, 0x3f8                      
                    la x18, data1                             
                    add x22, x22, x18                         
                    amoor.d x19, x20, (x22)                   
tc.bb3.l5:          bge x19, x18, tc.bb4                      
tc.bb4:
tc.bb4.l0:          andi x22, x22, 0x3f8                      
                    la x18, data2                             
                    add x22, x22, x18                         
                    sd x19, 0(x22)                            
tc.bb4.l1:          sltu x18, x19, x21                        
tc.bb4.l2:          fmv.x.d x21, f0                           
tc.bb4.l3:          call fn2                                  
tc.bb4.l4:          srai x22, x21, 26                         
tc.bb4.l5:          addiw x19, x21, 1309                      
tc.bb4.l6:          fmul.s f4, f2, f1, dyn                    
tc.bb4.l7:          fclass.s x19, f1                          
tc.bb4.l8:          fcvt.wu.d x18, f3                         
tc.bb4.l9:          andi x18, x18, 0x3f8                      
                    la x20, data2                             
                    add x18, x18, x20                         
                    amoand.w x19, x21, (x18)                  
tc.bb4.l10:         jal x21, tc.exit                          
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
fn0.entry.l0:       fmin.s f5, f8, f6                         
fn0.entry.l1:       lui x24, 860                              
fn0.entry.l2:       fclass.s x24, f5                          
fn0.entry.l3:       remuw x27, x23, x25                       
fn0.entry.l4:       mulhu x23, x24, x25                       
fn0.entry.l5:       xor x25, x24, x26                         
fn0.entry.l6:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       divw x23, x26, x27                        
fn1.entry.l1:       fnmsub.d f5, f8, f7, f6, rmm              
fn1.entry.l2:       fmv.x.w x25, f6                           
fn1.entry.l3:       fcvt.s.l f5, x24                          
fn1.entry.l4:       fnmadd.d f7, f6, f5, f8, rup              
fn1.entry.l5:       fcvt.wu.s x26, f9                         
fn1.entry.l6:       fmv.w.x f7, x26                           
fn1.entry.l7:       ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       srliw x26, x23, 17                        
fn2.entry.l1:       fcvt.d.lu f5, x25                         
fn2.entry.l2:       fmax.s f6, f9, f7                         
fn2.entry.l3:       srli x27, x24, 61                         
fn2.entry.l4:       fcvt.s.w f6, x25                          
fn2.entry.l5:       fsub.d f5, f9, f7, rne                    
fn2.entry.l6:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       fnmadd.d f5, f7, f8, f6, rdn              
fn3.entry.l1:       fmsub.d f5, f8, f9, f6, rtz               
fn3.entry.l2:       slliw x25, x23, 13                        
fn3.entry.l3:       sraiw x27, x26, 10                        
fn3.entry.l4:       fcvt.s.lu f7, x25                         
fn3.entry.l5:       fmul.d f8, f6, f7, rup                    
fn3.entry.l6:       fmadd.s f7, f8, f9, f5, rmm               
fn3.entry.l7:       fdiv.d f7, f8, f5, rtz                    
fn3.entry.l8:       ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       flt.d x24, f9, f5                         
fn4.entry.l1:       addiw x24, x23, 1437                      
fn4.entry.l2:       sll x25, x26, x24                         
fn4.entry.l3:       fcvt.w.s x24, f9                          
fn4.entry.l4:       lui x25, 1164                             
fn4.entry.l5:       fcvt.s.lu f6, x24                         
fn4.entry.l6:       fnmsub.d f9, f5, f7, f6, rmm              
fn4.entry.l7:       fclass.d x25, f8                          
fn4.entry.l8:       fdiv.d f5, f6, f9, rtz                    
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
    .dword 0x25ed8b4e4739a148, 0x367aec301f5beed5
    .dword 0x31e51e81eee21fae, 0x9a9f59e26e9b5e25
    .dword 0x886b78a77a36ef05, 0xcb63cf0dbbe8ee5d
    .dword 0x18865999ae293b05, 0x5a3e0ab69d8b7c22
    .dword 0xc309afa8b2866f46, 0xf153bb863d5dd635
    .dword 0x1f9f64eb310d8277, 0xa90b98d31b213831
    .dword 0xfa37ac103f803069, 0x7aac1170ebf51295
    .dword 0xb7b4a13f1eaeaaa7, 0x100b6c12279a2804
    .dword 0x8b167226b2c67d4f, 0x32955a990c8ab1a0
    .dword 0x5a2c13a50bdf8556, 0x4c953394bb12aa99
    .dword 0x819aca757edabe6d, 0xabe3b8a947776519
    .dword 0x73e872a939cac19d, 0x562f9324826ac374
    .dword 0xf32d995ff0df997, 0x1ab8ad27982fe516
    .dword 0xfbf9ebb82e0d1679, 0xce3dd6c3d1130cfa
    .dword 0x2aaaf7da48a48253, 0x3aed87383b8b5950
    .dword 0x691619cd8b47b593, 0x5c57b8e52c2f34e2
    .dword 0x56148ad31fd8fd15, 0x84f4407e4c0db9da
    .dword 0x6f692b2eb66b6b52, 0x2e0564619150e1b5
    .dword 0x589b0a0b1ed2b719, 0x9db4a62dd73e54e
    .dword 0x790277ec1637c5e2, 0x62830b51122897ba
    .dword 0xd2866bdf2c3246d5, 0x9cb22e07714dfa70
    .dword 0x25942d0b763ef583, 0x5f20bcd1b851c580
    .dword 0xa57c9e9ca792c14f, 0x4157f05376058a91
    .dword 0xaecadcb6bf718fa5, 0xa0a60aaf5df01275
    .dword 0x4523e08f209435f8, 0xa6978efee7d0978a
    .dword 0x362faa2abe7edb8f, 0xe78ec31f0d7c975c
    .dword 0xa2d79585fbc220a7, 0xfed0dc85431cbb9f
    .dword 0x312c0340de2bb0ed, 0xa9c70c106a59dea8
    .dword 0x18ea32aa2175a2f5, 0x48293404c1da08e4
    .dword 0x576240bc70d28d5d, 0xf4d47edd9972e4c
    .dword 0xcb8b6938a0476164, 0xe869d30d1ebf70a9
    .dword 0x721c34cf0f432f88, 0x2a2c6e612cba7ebe
    .dword 0x176195a5bc35f22d, 0xfc73af4ee37695e3
    .dword 0x5228b0b0b482f714, 0xd6c89a58fa7f0505
    .dword 0xc8c5ba67a3baf27a, 0x4684d38c643d56e0
    .dword 0xffcea20f738c1315, 0x2d6ed27ef92bc59e
    .dword 0xbbf17ba23b50760c, 0x362407a20606f90b
    .dword 0x7cb85eaf8494c01c, 0x89d8342c17112e6
    .dword 0x362edfcfb6776a58, 0x98fce0fcb0d247cf
    .dword 0x3fff7568c9476977, 0xdd0aae6b4fc5133d
    .dword 0xa4451a6cd0ba8cb2, 0x7cf8c829046decef
    .dword 0x64ad6e93d1f02fb, 0x31d7a98c8e55e62b
    .dword 0xc026a30a8d97256b, 0x86b727feaebf3a6f
    .dword 0xfb61c2dfd7f1c859, 0x17d9c8fe01adfd0c
    .dword 0xfa26e3e777cb0f54, 0xd10bc02c063f070b
    .dword 0x42a0f99d3c71a56e, 0x71c97ab6ae7eb976
    .dword 0xd143e0400c418a3a, 0x4435f4dd8eb516f8
    .dword 0xf56df2f97f95480c, 0x3b749468dce12ebd
    .dword 0xb4536e123e35d8bd, 0xbda90b01078440b0
    .dword 0xa4042b72ac35c31d, 0x702663998d588862
    .dword 0x20237093309b2e2f, 0xd0a986f312c35894
    .dword 0x58134ec8ade76a3e, 0x215f943e80c1da59
    .dword 0x92720a476353f501, 0xb38d2a9a8d44e77f
    .dword 0xb07fcd26f02d7ef6, 0x500839b6c74f1fa4
    .dword 0xe301c936de5c1eb5, 0x9280d2cd63ecc2db
    .dword 0x91e61e8b45ff9c26, 0x8da6d46e732af2aa
    .dword 0xf34f4d837c11c947, 0xf83b2bba120def66
    .dword 0xbfee46275a8238c3, 0x15809b3e0e45d32a
    .dword 0xd76f280bc8dca16e, 0x3e0c244d211eb794
    .dword 0xd0866da2a9b106d9, 0x71239f6bfdc773f0
    .dword 0xcc82e8490892f60d, 0xded707b2dd5e6951
    .dword 0x502b2be088432863, 0xff512f756823ae17
    .dword 0x3854c1503555c57b, 0x4093c0cd29b05561
    .dword 0x8accb3984d358cd0, 0x3506f82b81f71413

    .align 12
data1:
    .dword 0xdc7dbeb4fe219ece, 0xbfc5660d2d035405
    .dword 0x8d6c9e2185486024, 0x2f727925b2ab65cb
    .dword 0xf0474de1137a5813, 0x6cc86a460bed16a6
    .dword 0x1b6c5ef050d8fe3c, 0xa44efb68b584c505
    .dword 0x5574192e4df43660, 0x6239dedb64bafd08
    .dword 0xff4a7970e836d23e, 0xca39a1bb8a002a44
    .dword 0xc6b4285acd55728c, 0x74620917608c04db
    .dword 0x17d4fd0e86152a30, 0xb1bf4b95ec9a0441
    .dword 0xd0ae9e5f8449ab3d, 0x6e442d00e5f3b2dd
    .dword 0x5b1b3e56fb10c374, 0x5bc01d0b7dcea0cb
    .dword 0x93b9721ff06bdc22, 0x22a17e6fe2736860
    .dword 0xef021376a492f824, 0xb81c16ae68e37ba0
    .dword 0xac921ff570fdc658, 0xa1d17d858b9e148d
    .dword 0x2cd5b213da7626a3, 0x6d9f357c41aed037
    .dword 0x846f69eba7923d80, 0xf1d9a777d5518e46
    .dword 0xc075035b49c126d2, 0x195f9c37458e15ea
    .dword 0x36936e990cbd22ed, 0x67482b6188118945
    .dword 0x73c0e34f0672ee9b, 0x85b0550e009fef34
    .dword 0x99e8a8dfd8013f8d, 0xc00001009a099cdc
    .dword 0xe24230a7fd274bfc, 0x86b184abc7299f02
    .dword 0xd4d79ff0298502d6, 0x83eb90c730c4e2d
    .dword 0x6185b6d692bbab2, 0x7fc0973c78b64fef
    .dword 0xe4e2447793f75a1e, 0x39a9bc75e3960dec
    .dword 0x4c0fc9980c3fca63, 0x37374becf99c41fe
    .dword 0x661c631a97014339, 0xecd46b2fc746f71e
    .dword 0xb8462edfb554ef4e, 0xe1c0747dace2658b
    .dword 0xcd87e8bcb3c9d5f3, 0xafaab277be08df9b
    .dword 0xf5dbc02dea9668b6, 0x622537e09826534b
    .dword 0xfbbd28f73d5a700b, 0x7786068bb232ab60
    .dword 0x1316845db08b16b8, 0x95cd4fbb0f104148
    .dword 0x4c6fe492ee25d95a, 0xcc562efdcdee276e
    .dword 0xa4da298714e3d72b, 0xc0981f1a16a3398c
    .dword 0x6e03d6e2f6399db6, 0xeb30f4b582ffaa7c
    .dword 0x6237fd323b01de31, 0x8a1d7768e5386d1a
    .dword 0xd08fef21e6521d83, 0xde543fa2643df8ce
    .dword 0x4b84d64656643e7, 0x3fd6187ff275915f
    .dword 0xc400ca68b5c22482, 0x5b2dd9ce9dea6c17
    .dword 0x47b1a4fa80b9c376, 0x79f4a3368d5f8e1f
    .dword 0xb2d6b7a8bc4d58b2, 0xfa5d4af79bbdf611
    .dword 0x97820da7647185ce, 0xb44069b28861978b
    .dword 0xaadd57a0592c966f, 0xf06ddfb919b9e15c
    .dword 0xff3b6942d63b7ed7, 0xb69737c0e573e86a
    .dword 0x8fb1d8c3f483fb17, 0xee2c41de6cf3e82a
    .dword 0xdad96b4883a4ce66, 0x17f719f05ac939ed
    .dword 0xe9595de5e0a9fcc9, 0x6d7814e265b1acfb
    .dword 0x8eaeaa1bed01e5f, 0xb06e2039d128e81
    .dword 0xb838d5835ea7807e, 0x4b47432b10ff4e9
    .dword 0xb264329d52db408, 0x35a9f9a34b07bd1a
    .dword 0x1f9072bde4601907, 0xec76077989496ae3
    .dword 0x231b1cbc586e0b7b, 0x7ead5036a98987c5
    .dword 0xf49988da7843c41b, 0x2ee921f3a4f20956
    .dword 0x839cf6a414f185b8, 0xa70efedb7b200155
    .dword 0x48e42dfe5011a2, 0x952c00928cdc150d
    .dword 0xf5763faaa008aa59, 0xdd742faa2856f6ac
    .dword 0x1d38a9060bb5c4fb, 0x1396dd471ac3a825
    .dword 0xb4a4f2169844780c, 0xcae0fd3a045ba862
    .dword 0x9f04bcda3838b7d6, 0x39cbdf1bb072147
    .dword 0x5b047081a170b062, 0x8bebf2ddc24a0057
    .dword 0xe6a7f7060bfe37ce, 0x9db6eeea4442976e
    .dword 0x865ff9d061b972df, 0xfd91c3ba2e716cbf
    .dword 0x7c48719e14066005, 0x4c0867727fa59ba
    .dword 0x85b538f8c6ac9b86, 0x100adc858e516f83
    .dword 0xf31535b1ab0901ca, 0x4dacb93dee4ce6c3
    .dword 0xf56e477df18314b8, 0xd6809eb6fd1a7b04

    .align 12
data2:
    .dword 0x5bcdd4a4dbb01d16, 0xf2e0be13e2272f86
    .dword 0xe75abae361803704, 0xee2180d8987da05b
    .dword 0x3c80de19ef4efe4f, 0xa4e3df3aa7e44135
    .dword 0xdcd5e6c2d1fcb5fb, 0xaf217fa9574450e2
    .dword 0xe6a4be4f7be54e10, 0x92c0ef85e98db52f
    .dword 0x2083771f6194744e, 0x3761f3912dd8f905
    .dword 0xdc2070443067a480, 0xd4b704181f00e053
    .dword 0xb43e314009dd063c, 0xb6061a0002de1851
    .dword 0xd6bfa40db8958197, 0x7f575f47ecfbac5d
    .dword 0x62c7ba4c9884925a, 0xcd3d223954bac18f
    .dword 0xa79a4a8cfeefe5e6, 0xa97fea7a91be5015
    .dword 0x3aafe5cf5114e0b7, 0xec6cd71ad8d35dff
    .dword 0x99d5d5ce72cd3e20, 0x24d3560aaff6451a
    .dword 0xdf1d7c93ccca4dcf, 0xfd60d01e672ad8c4
    .dword 0x4a4328196c5e25a4, 0x6c1def5d48c9a289
    .dword 0x9d1983e8ef03e85, 0x66fe652623f03ca2
    .dword 0xce2d4296609a3da5, 0x772f6356dd7ca0c9
    .dword 0xa77bb9418a4076a4, 0x2f2c0b73da236c61
    .dword 0x45409ef28c695d99, 0x82ccb788cd12e2c2
    .dword 0x3bc68a00ca07af9, 0xd62259c60fc707b1
    .dword 0x82af857404982217, 0x139eb3712236614a
    .dword 0x4d0b04c0327629c7, 0xba718007d6324586
    .dword 0x747ad99210e6cf1a, 0xbd76faea35d3f64f
    .dword 0x818982e243422c4a, 0xd7a469c72cebb6c8
    .dword 0x1f8b86dd827ec9dd, 0xae764a4ddbb0b9cc
    .dword 0xdf9092c9eab18023, 0x6fdca2d8bf1d1059
    .dword 0xbce7ead3e4f02303, 0xd904f70d794dde73
    .dword 0xa0b2480961bdbb74, 0x3be20b6e554b9353
    .dword 0xdf1792e4d97cc08d, 0x5a5ca1c00d2d7441
    .dword 0x5f34d7df9ff4e9d3, 0x14138ee8e4eaff6a
    .dword 0x17afb2c611edb9e6, 0xa25ff418119bd48d
    .dword 0x947ebadb79ffa49b, 0x28082764ade09380
    .dword 0x5065f24ff81e4810, 0x5ab6edcdcebf653a
    .dword 0xfb977c6ce04f2d07, 0xa57a0ffd3defaa4d
    .dword 0xb88127b6e183edd2, 0x565752aa28c09810
    .dword 0x35173ece4d6a69f5, 0x15e921bf73107be4
    .dword 0x89794c25e93c7184, 0x82c831b4d2485eee
    .dword 0xa1e88f3d661a8094, 0x582b0b34f3874cd4
    .dword 0xe3a2e898744d0fb8, 0xed1b0e8cc544de1
    .dword 0x3d5cf1ffb33eaee0, 0xf31cf616368fc030
    .dword 0xabd3d45a92360238, 0xb1b67d1853711213
    .dword 0xa2483b20cb8bb5b3, 0xac03b3f1f07f6695
    .dword 0xd80019280861648c, 0xabc6e338d262877a
    .dword 0x797f676e6db5beed, 0xe24413eb796640cf
    .dword 0x40a217305425dc0b, 0x344ab66e90e78c83
    .dword 0x56b50b1c964dbb00, 0xd88496548ea3b008
    .dword 0x2a16ce160104781, 0xb4ebb49b287d2f25
    .dword 0x6ec701b7b9d112fa, 0x2c094851818e9c04
    .dword 0x7e2a9629465c46d7, 0x49bef094b4d6421b
    .dword 0x408e50121cb85d05, 0xdb5840cbc88f6375
    .dword 0x1c23cf216a358014, 0xc01125e494bb53d0
    .dword 0xfa40bd1db094c07d, 0xa7f19340c767e4ef
    .dword 0xffdcd34d21074303, 0x8d8bec2be6a01b8e
    .dword 0xd9e67f4bb55727ac, 0x3d3c1cb72635515c
    .dword 0x46fb74dbaf885822, 0xfcd31c55fd4d749f
    .dword 0x1e2196e73c78f51e, 0x9c3e7f740dc7b256
    .dword 0x5df4fab6fd560b12, 0xcbd27ea38457a937
    .dword 0x32b585723c70db58, 0x7006a2e8882e0fcd
    .dword 0xb5ee448be70d756f, 0xf3750006c40a49a2
    .dword 0x24ff91d1d5901423, 0xbcb0752f2270e721
    .dword 0xfb3eb8cad6a959eb, 0x6d650a51e7049a71
    .dword 0xd9bf7db173f41e6f, 0xbe6a616f131232fd
    .dword 0x785ed5ea599a0ee8, 0xdf87e481e899ab9c
    .dword 0x9b020a3d19193567, 0x233cbb8e3bc7a9e7

    .align 12
data3:
    .dword 0x620a5cbd09d3b02, 0xce954353c3817de0
    .dword 0x23b46bfb714568e8, 0xf599fa8f74dc6dd7
    .dword 0xb2d20e05aa99aef1, 0x4d0365d225547b7b
    .dword 0xa86d1112094de3da, 0x2a458623aad886d
    .dword 0xaa01ebf1478acfb5, 0xb56a33880f99ba16
    .dword 0x47264d3649e42c2b, 0x6b88ddb2bd5a82c7
    .dword 0x27e2cc9c11960040, 0xc00be1bf54674841
    .dword 0x8f136cf9e2aa90eb, 0xcc0680fad0a525cb
    .dword 0xb29f879f2fa91df5, 0xafbaac62f1c92e7
    .dword 0x88c74346127274f1, 0xa1601eb79ad210a6
    .dword 0x189e325d161dffd8, 0xa42d9d79ca2458e7
    .dword 0xbe325943654c62de, 0xe1790c94c7be8bb
    .dword 0xe68248e6df040970, 0xd4ce60ba0417dee6
    .dword 0x78314c10c1c73cfe, 0xa4de45d1031d31f5
    .dword 0x32d025563b7c9f48, 0x33308e4215ab53f6
    .dword 0x32b63c0b168428b6, 0x925adb6ce8e5c062
    .dword 0x9e3f9f56766211c9, 0x4b820065a1e6edac
    .dword 0x1e82fe2095713f8a, 0x2a598312dece5c46
    .dword 0xb9a043872827582a, 0x80d726ddf967a373
    .dword 0xb5077206625f6b5e, 0x4c1e0a4f821bfe5a
    .dword 0x1c593debb358e841, 0x5a1c88d1fe07f381
    .dword 0xca665314556ae15f, 0x864d1003d71a56d9
    .dword 0xff317756b057fbc1, 0xf83623b96fa34b3
    .dword 0xb76590320ee13e18, 0xb723e95d68e43a72
    .dword 0x91de8db80f414884, 0x7e465bb7d10beb2
    .dword 0xb74950dd0e0e5d82, 0xb2cd5c3351a8df6c
    .dword 0xd3c354ceac1996b2, 0xef8cd4f05f8f8c33
    .dword 0xb860250c2e1d8104, 0xc3c17652699c4d37
    .dword 0xbfe4836f363c2656, 0xcae2d695b64eea78
    .dword 0x8663f474a47e121a, 0x5fe67ad571a56249
    .dword 0xf62f43e71c3e464, 0x24913e3cdeeb51d7
    .dword 0xa89179bb2a7000a0, 0x4a91ad6dbb411f65
    .dword 0x87d9d6716ce19dbf, 0x335548538480068a
    .dword 0x397af5f83c580a0d, 0x4e934c8e67fbef82
    .dword 0x31d6a4f6ff4fc9c6, 0xe849a1d6acf4fdbe
    .dword 0xc580f6ea144063a8, 0xb0394758e704aeb
    .dword 0xebfd3d4bb6bc4d70, 0xf1188c085b976f13
    .dword 0x9128c22208629dd3, 0xfeb39282740836ba
    .dword 0xdecb440855b9bcc5, 0x94b838ff74b091ef
    .dword 0x2670f37f229ca5f6, 0x38f79caea11e29e
    .dword 0xe2c8326650a7c7ed, 0x7fbca811dcc92e5a
    .dword 0x86041280f6d6b1d2, 0x879495f4b61f637f
    .dword 0xd86ed30d6f3829, 0x8004d254ded6e652
    .dword 0xa685223c9e0684, 0x871ef4253b83fd46
    .dword 0xb621b0f2584fc463, 0x4f10fd3c7ae80623
    .dword 0x39c3c69c0f0f4dd1, 0xb1143eefd6d27567
    .dword 0x2e9313fec918b94d, 0x200a8acc60e2574a
    .dword 0xef4b4d949f849c3b, 0x9aa5aa1ed0a57c74
    .dword 0x480e2d5ca6bd836f, 0x576b421289e6a1e1
    .dword 0x241cbf4faf0aaec0, 0xf8ca1386a0100df7
    .dword 0xf00c68c50fa96c4c, 0x66692ca662fdb465
    .dword 0x8250714059a99424, 0xa54b5f8e1b86bee7
    .dword 0x1110761c652eec7d, 0x82ec92a64e55264c
    .dword 0xa285a8c096932bd0, 0xea82d3ee9267526d
    .dword 0xd2d20391e2705ff1, 0xd3a5bbbbb7b70867
    .dword 0xd8c85ab4b8a2f349, 0xa1209b41c687e36b
    .dword 0xeeb6c394e3aaabed, 0x55b616859ef89e30
    .dword 0x3c194dcc041702e1, 0xd5df7efb5242b79c
    .dword 0x148016d9215d32f5, 0x7f0fb9fd1082b664
    .dword 0x4397e8b4879e60b8, 0x5cc369fde977d3d
    .dword 0xb892a5f990e25d75, 0x4c716918339075c7
    .dword 0x677a04e5c1040e17, 0xdfb2bee23cec24cf
    .dword 0xd856b3d0f815cf29, 0x2ccf288d453631d8
    .dword 0x62fbaf0cd663ee13, 0x1c847890d6404bbf

    .align 12
data4:
    .dword 0x108de1a6b1b5a854, 0x2737348c93b3c515
    .dword 0xccf670fc8df16cf6, 0x15144ed4f9972a72
    .dword 0xc6f9f7dde105c3dc, 0xc96ad66caf4b3d75
    .dword 0x58ad30be843b2c8f, 0xfb90ef8ee5ad17bb
    .dword 0x29c0ba03db85373e, 0x86321a3e2ed314d1
    .dword 0xd6c1d8d0c883475d, 0xd419e93b5bd78216
    .dword 0x4f5ce0c717eeeb0b, 0x1d219d841329716
    .dword 0x8c7a6419c00a759, 0xf7d10890605654a4
    .dword 0x7d385abe122b7a54, 0x85db2ebe9025d809
    .dword 0xaa5064507f54ca42, 0xe8e49876feda7ef
    .dword 0xac3e62f42087597a, 0xd3047dd71cde34f3
    .dword 0xbc22b89cb45cb862, 0x6659874067451bf6
    .dword 0x7cd075516b4e9f0e, 0x5233b1976115bd85
    .dword 0x2807524aa0762521, 0x33bc20a8a8a070f0
    .dword 0x41c73de6b57547c3, 0xaac8b19ea3df71b8
    .dword 0xac6c33dad5a1a2c, 0xa063310ffb71b758
    .dword 0x320fed6c6f1d2376, 0x55cca5e76b30a1f3
    .dword 0x7658684aab89636e, 0x7e3de9f7b2bdeb5d
    .dword 0xbff203d6cf871df4, 0x97b808a0e6f347af
    .dword 0x8fd4de08530b3224, 0x10b68947f36c1f9c
    .dword 0x83ca4c3a4617696d, 0x55d6dffcc9516841
    .dword 0x8118571f333225a6, 0xc539092665230064
    .dword 0x662c36d81fdf7248, 0x8c48a84c0a60db40
    .dword 0xf222db0d1da2436, 0xa5db58139d646455
    .dword 0x89defbe783153ae2, 0x19fda0d238e0a259
    .dword 0xaa6832849f3fe4b5, 0xe5821d2ab956b23
    .dword 0x3aba45c8a05efaa1, 0x73bad6225a4e67be
    .dword 0xf7ce2c08bc349588, 0xd7ae9a56ff521f95
    .dword 0x867c271420f03b72, 0xa5fda6b13d86c49e
    .dword 0x9f160b0cfaefdf9e, 0x5bd20e37c9d7bdce
    .dword 0x9f160de1730eac27, 0x29e632fa07bfc087
    .dword 0x8c6553cd5d2d1188, 0x33cc199cbe5ebd1e
    .dword 0xe57034861b2bc193, 0x239d5c50017c5cea
    .dword 0x16c8165171981ad1, 0x91c3d2335e14288e
    .dword 0xc6cb05a0c0363f6d, 0x5e7ecbc1803a26a8
    .dword 0xb7d4333730f1ee7a, 0xbfbe77b14e2900a8
    .dword 0x28b8d0202bc91492, 0xc9f948036660954a
    .dword 0x6ead11eb1c712d44, 0x81753ff6c1a396a3
    .dword 0x86f92c90ac9f470, 0xabf0ac8197670c7d
    .dword 0x446de110782d3789, 0xd0008cdc4fef92ef
    .dword 0x31bb80c218f8313b, 0x9ba79f5e42b2b03e
    .dword 0x17763104b2d343c, 0xac4e9c208abcd24e
    .dword 0xd8bd7cb2ebe5c398, 0xec97eeacc384382a
    .dword 0x728f0fafc42e810c, 0x4586f814330e1f28
    .dword 0x963508dbbfc161cf, 0x4a658a921a08aecd
    .dword 0x27d554a2e49f9718, 0xbbb954299a968adc
    .dword 0xd450aa3c3b3579b1, 0xde01b053ea6598af
    .dword 0x80ede4de7424976, 0x91c33f4afb9b95ed
    .dword 0xb37419f5216f781a, 0xe5045ccbd6948ff2
    .dword 0xeea023e1028a9dd6, 0x939e380b51afb30d
    .dword 0x9747476c59e5f8e7, 0xc3f89e34bac50bd4
    .dword 0x91a25f0ce9d7d596, 0x3d7d03e2cc68231a
    .dword 0xef5601da13f391da, 0xe410f31c029f8acf
    .dword 0xac4bed3412fecab9, 0xeb88e67ef7d284d7
    .dword 0xc3c0e27e5715e56f, 0xc80ebfc831922241
    .dword 0xfb763bddc3ed6e95, 0x519d6994c5eab776
    .dword 0x6546b46b378a3b3b, 0x49a5c0841a9df528
    .dword 0xb55c51519f778dfe, 0x75c766d22124feb8
    .dword 0xed3715032e4a7028, 0xc8b4932ad2bb6a65
    .dword 0x2162a093671b1a0e, 0x5cf928ac205be225
    .dword 0xe4e2fb07a9c89c7a, 0xf8c5dcc372d030a8
    .dword 0xc112d9db39cb5bb3, 0xb0d69e7a6a03ff28
    .dword 0xf001a6d00b819b36, 0xcef7f8d677e3bd9e
    .dword 0xd35965127712efae, 0x62f3083a1c7dbb2c

    .align 12
data5:
    .dword 0xf1f444e1aa05ef3f, 0xf57fa123201765cb
    .dword 0xc596cb4839d44e53, 0x6faab3eb654f6664
    .dword 0x56c384175df47546, 0xaf252be287c788dc
    .dword 0x2b0e897be8beb993, 0x556552d6b58f9e54
    .dword 0x793a811ce9587d70, 0x631112353fe734fb
    .dword 0xe4fe20d8ccf43dd9, 0xee3fa22e0a662a64
    .dword 0xd32f0efb136d2f9a, 0x1fb2247bc272fe96
    .dword 0x474b17ef1c67b52f, 0x525ad168f0647940
    .dword 0x38f147730200c62, 0xeeafc1177e4bc157
    .dword 0x4e0de2cce37639c0, 0xd40a32d54c841969
    .dword 0xfa13ad367da0c2b9, 0x3028e65b8b75a699
    .dword 0x64d435b86ea75cd6, 0x50e33c8fba2f8613
    .dword 0xffd454cf4cfd87db, 0xd11b2d8413b47f7a
    .dword 0xc99303ef060229e0, 0x3a1001edc53cdc3
    .dword 0x66c22bffd04e8a13, 0xac13e4e71b2b1239
    .dword 0x443eae7a42209a39, 0x7a86cfd671565276
    .dword 0xa31801bb66945df8, 0x94bdfa50a169ba95
    .dword 0x562297c2631c03ef, 0x4f0d65c39fa8f63e
    .dword 0xa72124b5454b280e, 0xb9dc6e7d9c8a95cf
    .dword 0xd6d1b743626fb64, 0xcfd1e84ca6099dcf
    .dword 0xdddef34d39841070, 0xf93135dbf1639d64
    .dword 0x9d892fc69d354434, 0xd250aad03ea5ad5e
    .dword 0xf6ea9f1ae81b71ed, 0xeaaac580fb4da32
    .dword 0x905f529b46a4c9ef, 0xfc77e54df366c83
    .dword 0xf79c123783cf26a0, 0xf760601745ee82b0
    .dword 0x3e7afd9d4fcc9b2e, 0xbc49ebdbe73d6041
    .dword 0xf2140a9fb0c1404, 0xfa1e42083fa55c0c
    .dword 0xf7ae0c6bec8b2e4b, 0x9f5c29a70eb71d5c
    .dword 0xd718243dfe5407b2, 0x5df274130f9b07c4
    .dword 0xc93762ff57ed7c78, 0x28a5c45922e11d52
    .dword 0xd283acc8e26bb138, 0x9584584b030eb3d
    .dword 0xd1fc08d01a91b739, 0xc8d5ee890f0f1817
    .dword 0x443a4c9bee50dd19, 0x78f65bebf7b4fbd6
    .dword 0x212028a9de1acc60, 0xd7040a2195d93d18
    .dword 0x6e755809fb0cc40a, 0x8bd65c8a21cc8dee
    .dword 0x19f608399195165b, 0x53663fabe3c38b4e
    .dword 0x117f32c133163e09, 0xea21f3b19ab17d27
    .dword 0x3f7d5d3597aef37d, 0xd5b5301adc6ad1e9
    .dword 0x70258ca4011974d1, 0xba2afabb27d64e6b
    .dword 0x91d1540fd0ee8551, 0x1ef3446427596afa
    .dword 0x500405ae84283876, 0x97a380c6494e17b
    .dword 0x3c0b6beeab451630, 0xa037cf7e75370e16
    .dword 0xe30a379e64c3f4c4, 0x61d10899165ef32c
    .dword 0x92757bdc7c5e9c55, 0x1434fcdc707812df
    .dword 0xd6fa74ccb738314f, 0x66741cb7eb9b6936
    .dword 0xc0c2f9a781812690, 0x11b265744bb56595
    .dword 0x1137d197a4acdcda, 0x56aa58403e409496
    .dword 0x463b11c8d811c68b, 0x7de503e6744d2624
    .dword 0x82cdba1ff1c4a472, 0xf9426a1d37bf625c
    .dword 0x35b8d69a8739483f, 0xea3f858804197953
    .dword 0xc4b8aef306b4c3ee, 0xeded7139f47ec553
    .dword 0xe067ab692a17684d, 0x6485cc3eadd25a43
    .dword 0xaea061fbe53d164b, 0xe42625612556dad7
    .dword 0x20fa5c684a79b6a4, 0xd5df6d4a4ffde7df
    .dword 0x7dedd068f820ddc3, 0x22f4be9ba5ae5a73
    .dword 0xa2eb74f2820af0a9, 0x824d2f3c428c23e9
    .dword 0x5d402bc3085a1059, 0xbb2a089661f384b5
    .dword 0xcfd13878c095701b, 0x9f975b6d09ca5bdb
    .dword 0x5ebe777b142ffede, 0xb481494ffb57f87f
    .dword 0xef84a41d1ad2e26f, 0xc8b24f09ebe55201
    .dword 0x2188760de55c695b, 0x2e5880f83323ce41
    .dword 0x5a128057dde96409, 0x5445a72f9884746b
    .dword 0x3e9e751f280350a, 0x40d60242db3fac3e
    .dword 0x9a3a34e56275956b, 0xc1784ed3fe22f34a

    .align 12
data6:
    .dword 0xb4c1554603db8f1b, 0x4a7bf955ad006bbc
    .dword 0x2b35c11c6db70c3, 0xa6b082e40a7677fc
    .dword 0x83dd1e17441d82f7, 0xb7811009011276de
    .dword 0xadd63b206bc6c870, 0xc0248815189e4401
    .dword 0x95f83fa0829f1a7b, 0xa3cd82710074869f
    .dword 0x7977f2227f3dbf4c, 0x2b6aae6e75cadf0e
    .dword 0x9c9c329ad2557759, 0x6189d6765cab035b
    .dword 0x3d4f4ac8b07ce20f, 0x383dcda42926f9bc
    .dword 0x636e11caa1b50082, 0xac963bcf5658cbcf
    .dword 0xa895ac0659d0f539, 0x8cf036f481422346
    .dword 0x7803f1ccf61f2987, 0xc8a39e3cb032b2fc
    .dword 0x5ef675d9e2b52177, 0xe9d7d4dfa250a2d4
    .dword 0x21f896e1456e3821, 0xaddb3758c67a7b80
    .dword 0x1bcf3f4f3a4068e1, 0x2c8fdc3f7c900a2b
    .dword 0xbc1d62aa6007247, 0xd901f162697c76be
    .dword 0xb7490dfe97d3c0a1, 0x7e4b05fb89969fe2
    .dword 0x80154855eeb08efd, 0xff8820cfb547d37f
    .dword 0xa6d55c85ffb6c9a8, 0x2e74f3a84f3f338f
    .dword 0x6aace91f05c0b52d, 0x90043ae28017cda8
    .dword 0x7b67091836ded93, 0xb89b794da93e8ba2
    .dword 0xa0556bfb77b28cc4, 0x96908b96219c8be1
    .dword 0x7ce17c0962f02293, 0x67904ddaab158376
    .dword 0x8eef1183ebeb78ad, 0xf636fe23b0f141cc
    .dword 0xd2687886f31b7532, 0x2365da82195a1cc3
    .dword 0x6edbb375ae04ce57, 0x31b6216a4be731db
    .dword 0xfc74b0a1f617d73b, 0xb9f01d0b884242e
    .dword 0x2bca67979adae4ca, 0x53dec97b4b7ca9b1
    .dword 0xc89905c353ab3bb9, 0xbce717da8673bb78
    .dword 0xe041fcc42fba3ba7, 0x3db5f3156fbdd528
    .dword 0x7d8b7e68478387dd, 0x8e54a0bb7e9d75f3
    .dword 0x2e95aa5d23db6a3d, 0x629632d62f65d321
    .dword 0x25c5a7d90d342cd4, 0xadaef3915c6e4eac
    .dword 0x10988d388edb5582, 0xe4b984bfb024fb04
    .dword 0xd4771b7f436df213, 0x8fd8690a0a44b3b6
    .dword 0x60eb95957f552d85, 0x27f16a13c430258b
    .dword 0xe16c2f6024b58504, 0x632dc00894bc5c04
    .dword 0x3da947b7d9f9e06d, 0xfc91db6dc81a227d
    .dword 0x353f53d06bdb87a8, 0xa595f462c441f9f
    .dword 0x48202cd85857a7f8, 0xc6a31e22f0dcd601
    .dword 0x392410b1728d1907, 0x52060fafcb2ba496
    .dword 0x2ac569ce24c6b3a5, 0xf2d9179d243828c5
    .dword 0x56413a1a3e4f71ec, 0xb94967597a9a7123
    .dword 0x6ce047505735ad00, 0x702413a932603e5
    .dword 0x7ddc94638a2eb932, 0x228c54368915900f
    .dword 0xc30c72303105ce16, 0xd5bdf8da734414ec
    .dword 0xd5309ab8ff60cbb0, 0xa1b99354dd511c0
    .dword 0x2283e50ad8a869a8, 0xf27ff79039939d62
    .dword 0x416eed7da47611a8, 0x6d6954107b3ae441
    .dword 0xa0d665ad56c4688c, 0xaf21a5008e8cee91
    .dword 0x5fe7c0219c9c8449, 0xd476160e34b5fb06
    .dword 0xe57ea2ec2b59eb3f, 0xe164783bcb47af5a
    .dword 0x5326eebd55b27971, 0xb0557517e7c83973
    .dword 0x8f13792db196b237, 0x320d0cf36c8745a4
    .dword 0xe1a5387ffc9d867b, 0x95d92b2261c60b67
    .dword 0xcc848375b3a01d97, 0xcddcd7fdef3353c2
    .dword 0xdd4ab5d864f888f7, 0xadc482db29ce21c1
    .dword 0xa682dc1e99a3ed19, 0x9772ce1eef0eee37
    .dword 0xc3645191be097fb9, 0x96a2ab508a97a09b
    .dword 0x725d789802a7742c, 0xd672f47f54e32d8b
    .dword 0x3c4756bfdb908fa6, 0x624ea8acf8b4cb56
    .dword 0xaa9d21794df87dd6, 0x60c29ae92307b940
    .dword 0xaa2b206a5d73b2f9, 0xadb51a626a55eee4
    .dword 0xaac25bec5500f290, 0x844ad97ff3a8d031
    .dword 0x38a6cdca8083dac7, 0x9835dbdab891ffe2

    .align 12
data7:
    .dword 0x43f55b97102ec488, 0xe82dede1c383d59b
    .dword 0x67ffa1ff4154d31d, 0xba4faa232395944e
    .dword 0xa7fb3aecbb68ba6f, 0x4599f18caaf3c833
    .dword 0x79f51c3e3a2f3dcc, 0xd318be295313d653
    .dword 0xebc4b8823d12431c, 0x8d1909840afa1541
    .dword 0x5dba0b7178c7689b, 0x2beeb7379c5257e6
    .dword 0xd5bc081ffc1cc9a1, 0xd16ed91ed639c2d0
    .dword 0xd3e7107bfb242d15, 0x6e4604e230b5422c
    .dword 0x7c7d6649ae911230, 0xb28dadd806a5744d
    .dword 0x7cf20747d9635b53, 0x3288b1fc502f07b7
    .dword 0x97a548efcbffe02f, 0xb54a5633aed37164
    .dword 0xc1462dd02fc08b76, 0x5cd5001cdb561f17
    .dword 0xc5240e89b0a7a6d9, 0xb6d41f1a32a74cc2
    .dword 0x4cff0140c398d683, 0xf1ee65390f247398
    .dword 0x698ca923a178af63, 0x5ebf953bada0ff46
    .dword 0x24dcbc463089df0, 0xba3acecbde9bc92
    .dword 0x35ef890a646b6455, 0x784404b717fae84c
    .dword 0x22bad7f5de8fe3af, 0xd1a7137dc7b8d7fa
    .dword 0xd79a977055ea2c9a, 0x5981b1a1fed88ce2
    .dword 0x4abea8ad7700523b, 0xb1445c77d83e57ba
    .dword 0xa7e8c694ed585f4f, 0x6dda718ea84aa4a2
    .dword 0xe02a87f1a7951723, 0x1b41f2ddb25d0ae7
    .dword 0x3dfefb85004c6c8a, 0x20f2797acf2d8784
    .dword 0x7c2e976b04029611, 0xd5588b51d34e759a
    .dword 0x93806630122db888, 0x33ed9c7214861a96
    .dword 0x7ee6ada19b5a8dd0, 0xcff909a63f52680a
    .dword 0x6fd6b4479e5504fa, 0x3ff43d3ea4bc3e2a
    .dword 0x73ba1506ed3cfde9, 0x93efbfe8c549bc75
    .dword 0xb9a3a3c9a57f9e9, 0x6a9af46428b4495c
    .dword 0xd200d417160786b4, 0xb00c56a25fc50d10
    .dword 0x873bdf896c609cb5, 0xc7bede5e71d941cb
    .dword 0xd5c3374ffaf31210, 0xae5511622b037422
    .dword 0x11019e481c657551, 0x7ac10b595817e433
    .dword 0x839893e3982f517e, 0x3b015ff9b20eb271
    .dword 0x8ade070c8f255562, 0x5c496c64c5412118
    .dword 0xebfcd5150cc39851, 0x813fbdb07f1d945b
    .dword 0x9cbef9ab48384540, 0xb6f5c5e6d3a27ec8
    .dword 0xca00e7153637c853, 0xe32ca0f2a990619b
    .dword 0x216c413a6ccd8a6, 0x6f55572982ae1e02
    .dword 0x4089646ac70a6a3a, 0xe4bdfeb4a9576866
    .dword 0xe879716e8cb3b5c, 0x52ab6b56ed71a322
    .dword 0xd0dcca64b1e5acd6, 0xe61e5be78f8eecc5
    .dword 0xb105e8cbd4220b6a, 0x8defa223e7433bdf
    .dword 0xd419c28589a8e05c, 0xbaa8902f2514214c
    .dword 0x1cfa5055ed2677e8, 0xbd993a15373ec928
    .dword 0x3003949d149c92bd, 0xd16f212d1ce7d2d1
    .dword 0xeda43f6cf0ba5960, 0xfa09b1f2d4341597
    .dword 0xc4aab34e164a23c5, 0xde801eaa17e08edc
    .dword 0x7a774fa81beb822d, 0x5a9f297cbd9fc896
    .dword 0xb38e9cb61d4240c9, 0x2d6ebadc910e3a54
    .dword 0x484649e96ddba9a9, 0x6f6ac3df250f1c06
    .dword 0xc5bfecfcb57af8af, 0x7e7386ca9ea96f48
    .dword 0x8d299e3aa15a4ad, 0xb223a3e106b5b57e
    .dword 0x52b39fde062b5026, 0x7eb4390956fe4f25
    .dword 0x9408898ebd625cfd, 0x7b2ce4b352a06adf
    .dword 0x665fc7b91937ffb2, 0x47e2a1814f59be83
    .dword 0x8d8d6ab62395c0fc, 0x41f0eaa1b0c3072b
    .dword 0xd585e51a13949795, 0x8a58e480a50930bf
    .dword 0x6c2487303dd70cea, 0x5e7660834a3dd385
    .dword 0xa56f57a71976b77, 0x1e0bf8e447c80ac
    .dword 0xfc7422e90f07cc63, 0x3f5643d4f7450876
    .dword 0xb87c457e3b12d370, 0xa12ecbb70e6d0a8e
    .dword 0x917b3e57e0227cf9, 0x770b8e4aafb61d42
    .dword 0x5e25a66872d61b70, 0x74bbbda358af7043


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
