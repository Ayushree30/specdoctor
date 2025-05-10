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
                    fld f0, 8(x19)                            
pfx.bb0.l1:         andi x20, x20, 0x3f8                      
                    la x21, data2                             
                    add x20, x20, x21                         
                    fld f1, 16(x20)                           
pfx.bb0.l2:         andi x18, x18, 0x3f8                      
                    la x21, data2                             
                    add x18, x18, x21                         
                    fld f2, 8(x18)                            
pfx.bb0.l3:         andi x20, x20, 0x3f8                      
                    la x21, data4                             
                    add x20, x20, x21                         
                    fld f3, 16(x20)                           
pfx.bb0.l4:         andi x21, x21, 0x3f8                      
                    la x20, data0                             
                    add x21, x21, x20                         
                    fld f4, 16(x21)                           
pfx.bb0.l5:         andi x21, x21, 0x3f8                      
                    la x18, data6                             
                    add x21, x21, x18                         
                    fld f5, 16(x21)                           
pfx.bb0.l6:         andi x21, x21, 0x3f8                      
                    la x22, data1                             
                    add x21, x21, x22                         
                    fld f6, 16(x21)                           
pfx.bb0.l7:         andi x20, x20, 0x3f8                      
                    la x22, data2                             
                    add x20, x20, x22                         
                    fld f7, 16(x20)                           
pfx.bb0.l8:         andi x22, x22, 0x3f8                      
                    la x19, data0                             
                    add x22, x22, x19                         
                    fld f8, 0(x22)                            
pfx.bb0.l9:         andi x20, x20, 0x3f8                      
                    la x22, data1                             
                    add x20, x20, x22                         
                    fld f9, 0(x20)                            
pfx.bb0.l10:        addi x18, zero, 1958                      
pfx.bb0.l11:        addi x19, zero, 223                       
pfx.bb0.l12:        addi x20, zero, 718                       
pfx.bb0.l13:        addi x21, zero, 1539                      
pfx.bb0.l14:        addi x22, zero, 1198                      
pfx.bb0.l15:        addi x23, zero, 149                       
pfx.bb0.l16:        addi x24, zero, 2019                      
pfx.bb0.l17:        addi x25, zero, 580                       
pfx.bb0.l18:        addi x26, zero, 591                       
pfx.bb0.l19:        addi x27, zero, 1056                      
pfx.bb1:
pfx.bb1.l0:         addi a0, zero, 1200                       
pfx.bb1.l1:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 16(a0)                             
pfx.bb1.l2:         addi a0, zero, 1815                       
pfx.bb1.l3:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 24(a0)                             
pfx.bb1.l4:         addi a0, zero, 145                        
pfx.bb1.l5:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 16(a0)                             
pfx.bb1.l6:         addi a0, zero, 577                        
pfx.bb1.l7:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l8:         addi a0, zero, 854                        
pfx.bb1.l9:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 8(a0)                              
pfx.bb1.l10:        addi a0, zero, 574                        
pfx.bb1.l11:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l12:        addi a0, zero, 1559                       
pfx.bb1.l13:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l14:        addi a0, zero, 963                        
pfx.bb1.l15:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 24(a0)                             
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
prp0.entry.l0:      nop                                       
prp0.entry.l1:      nop                                       
prp0.entry.l2:      nop                                       
prp0.entry.l3:      nop                                       
prp0.entry.l4:      nop                                       
prp0.entry.l5:      nop                                       
prp0.entry.l6:      nop                                       
prp0.entry.l7:      nop                                       
prp0.entry.l8:      nop                                       
prp0.entry.l9:      call fn1                                  
prp0.entry.l10:     call fn0                                  
prp0.entry.l11:     call fn3                                  
prp0.entry.l12:     sub x21, x20, x22                         
prp0.entry.l13:     fcvt.d.l f0, x18                          
prp0.entry.l14:     slliw x20, x18, 4                         
prp0.entry.l15:     bgeu x19, x18, prp0.bb0                   
prp0.bb0:
prp0.bb0.l0:        fcvt.s.l f4, x19                          
prp0.bb0.l1:        fdiv.s f2, f1, f3, dyn                    
prp0.bb0.l2:        div x22, x19, x18                         
prp0.bb0.l3:        call fn2                                  
prp0.bb0.l4:        addi x22, x20, 1359                       
prp0.bb0.l5:        fdiv.s f1, f3, f0, rdn                    
prp0.bb0.l6:        fmv.w.x f0, x20                           
prp0.bb0.l7:        blt x18, x19, prp0.bb2                    
prp0.bb1:
prp0.bb1.l0:        fmul.s f3, f1, f2, rne                    
prp0.bb1.l1:        call fn0                                  
prp0.bb1.l2:        fclass.s x20, f3                          
prp0.bb1.l3:        fcvt.lu.d x21, f3                         
prp0.bb1.l4:        fmadd.s f2, f1, f0, f4, rtz               
prp0.bb1.l5:        fsgnjn.d f1, f2, f3                       
prp0.bb1.l6:        ori x20, x21, 1539                        
prp0.bb1.l7:        bge x21, x20, prp0.exit                   
prp0.bb2:
prp0.bb2.l0:        bge x18, x21, prp0.exit                   
prp0.bb2.l1:        beq x18, x22, prp0.bb3                    
prp0.bb2.l2:        fmv.d.x f4, x21                           
prp0.bb2.l3:        and x20, x18, x21                         
prp0.bb2.l4:        mulhsu x20, x18, x21                      
prp0.bb2.l5:        blt x19, x20, prp0.exit                   
prp0.bb3:
prp0.bb3.l0:        fcvt.lu.d x21, f0                         
prp0.bb3.l1:        bltu x20, x21, prp0.exit                  
prp0.bb3.l2:        bltu x19, x21, prp0.exit                  
prp0.bb3.l3:        fcvt.w.d x22, f2                          
prp0.bb3.l4:        fmul.d f0, f4, f2, rmm                    
prp0.bb3.l5:        bne x18, x22, prp0.exit                   
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      nop                                       
prp1.entry.l1:      nop                                       
prp1.entry.l2:      nop                                       
prp1.entry.l3:      nop                                       
prp1.entry.l4:      nop                                       
prp1.entry.l5:      nop                                       
prp1.entry.l6:      nop                                       
prp1.entry.l7:      nop                                       
prp1.entry.l8:      nop                                       
prp1.entry.l9:      fmax.d f4, f2, f0                         
prp1.entry.l10:     call fn2                                  
prp1.entry.l11:     addi x18, x19, 873                        
prp1.entry.l12:     addi x18, x22, 114                        
prp1.entry.l13:     call fn0                                  
prp1.entry.l14:     fnmsub.s f0, f4, f1, f3, rtz              
prp1.entry.l15:     call fn4                                  
prp1.entry.l16:     fmsub.d f2, f1, f3, f4, rdn               
prp1.entry.l17:     feq.s x18, f3, f1                         
prp1.entry.l18:     and x18, x20, x19                         
prp1.entry.l19:     blt x21, x22, prp1.bb2                    
prp1.bb0:
prp1.bb0.l0:        bge x19, x21, prp1.bb1                    
prp1.bb0.l1:        feq.d x18, f4, f1                         
prp1.bb0.l2:        fmin.d f4, f1, f2                         
prp1.bb0.l3:        call fn4                                  
prp1.bb0.l4:        fcvt.d.lu f2, x22                         
prp1.bb0.l5:        fcvt.d.w f3, x21                          
prp1.bb0.l6:        fclass.d x21, f3                          
prp1.bb0.l7:        blt x22, x18, prp1.bb2                    
prp1.bb1:
prp1.bb1.l0:        fcvt.wu.s x19, f3                         
prp1.bb1.l1:        divuw x19, x22, x20                       
prp1.bb1.l2:        sltu x20, x19, x21                        
prp1.bb1.l3:        fcvt.d.w f1, x20                          
prp1.bb1.l4:        fsgnjn.s f2, f0, f1                       
prp1.bb1.l5:        mulhu x22, x19, x18                       
prp1.bb1.l6:        flt.d x21, f2, f4                         
prp1.bb1.l7:        call fn3                                  
prp1.bb1.l8:        bge x19, x18, prp1.bb2                    
prp1.bb2:
prp1.bb2.l0:        beq x22, x20, prp1.exit                   
prp1.bb2.l1:        slti x19, x21, 636                        
prp1.bb2.l2:        srliw x19, x21, 26                        
prp1.bb2.l3:        fcvt.lu.s x22, f2                         
prp1.bb2.l4:        call fn3                                  
prp1.bb2.l5:        fcvt.w.d x20, f3                          
prp1.bb2.l6:        fmsub.d f1, f0, f3, f2, dyn               
prp1.bb2.l7:        fcvt.wu.d x21, f4                         
prp1.bb2.l8:        blt x20, x18, prp1.exit                   
prp1.bb2.l9:        fcvt.s.wu f1, x20                         
prp1.bb2.l10:       blt x20, x18, prp1.exit                   
prp1.bb3:
prp1.bb3.l0:        remu x22, x18, x19                        
prp1.bb3.l1:        fsgnj.d f1, f3, f2                        
prp1.bb3.l2:        fence.i                                   
prp1.bb3.l3:        fnmadd.d f4, f0, f2, f3, rdn              
prp1.bb3.l4:        auipc x21, 472                            
prp1.bb3.l5:        fcvt.wu.s x22, f1                         
prp1.bb3.l6:        and x20, x22, x19                         
prp1.bb3.l7:        fcvt.d.lu f0, x21                         
prp1.bb3.l8:        fmax.s f2, f1, f3                         
prp1.bb3.l9:        sltu x20, x18, x19                        
prp1.bb3.l10:       bltu x18, x21, prp1.exit                  
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        fsgnjn.d f2, f4, f0                       
tc.entry.l1:        fmul.s f1, f0, f4, rmm                    
tc.entry.l2:        slt x20, x22, x19                         
tc.entry.l3:        mul x20, x20, x30                         
tc.entry.l4:        mul x19, x19, x30                         
tc.entry.l5:        srliw x21, x20, 16                        
tc.entry.l6:        call fn4                                  
tc.entry.l7:        mul x18, x18, x30                         
tc.entry.l8:        srli x19, x22, 40                         
tc.entry.l9:        mul x18, x18, x30                         
tc.entry.l10:       divuw x22, x20, x18                       
tc.entry.l11:       beq x22, x20, tc.exit                     
tc.bb0:
tc.bb0.l0:          fle.d x20, f4, f1                         
tc.bb0.l1:          mul x21, x21, x30                         
tc.bb0.l2:          call fn2                                  
tc.bb0.l3:          mul x22, x22, x30                         
tc.bb0.l4:          mul x21, x21, x30                         
tc.bb0.l5:          mulhsu x19, x20, x18                      
tc.bb0.l6:          andi x19, x19, 0x3f8                      
                    la x20, data7                             
                    add x19, x19, x20                         
                    sc.w x21, x18, (x19)                      
tc.bb0.l7:          andi x20, x20, 0x3f8                      
                    la x22, data7                             
                    add x20, x20, x22                         
                    sw x21, 16(x20)                           
tc.bb0.l8:          mul x20, x20, x30                         
tc.bb0.l9:          andi x18, x18, 0x3f8                      
                    la x19, data6                             
                    add x18, x18, x19                         
                    lhu x22, 8(x18)                           
tc.bb0.l10:         fsgnjx.d f4, f3, f1                       
tc.bb0.l11:         bge x18, x21, tc.bb1                      
tc.bb1:
tc.bb1.l0:          andi x21, x21, 0x3f8                      
                    la x22, data2                             
                    add x21, x21, x22                         
                    lb x19, 29(x21)                           
tc.bb1.l1:          mul x20, x20, x30                         
tc.bb1.l2:          bltu x20, x19, tc.bb2                     
transient:
tsx:
tsx.entry:
tsx.entry.l0:       andi x25, x25, 0x3f8                      
                    la x27, secret                            
                    add x25, x25, x27                         
                    lhu x26, 0(x25)                           
tsx.entry.l1:       fadd.d f7, f6, f8, dyn                    
tsx.entry.l2:       srli x25, x26, 4                          
tsx.entry.l3:       fcvt.l.s x26, f9                          
tsx.entry.l4:       srai x23, x25, 58                         
tsx.entry.l5:       bge x24, x23, tsx.bb0                     
tsx.entry.l6:       slli x24, x26, 31                         
tsx.entry.l7:       bge x27, x25, tsx.exit                    
tsx.bb0:
tsx.bb0.l0:         andi x27, x27, 0x3f8                      
                    la x25, data7                             
                    add x27, x27, x25                         
                    amoor.d x23, x26, (x27)                   
tsx.bb0.l1:         beq x23, x25, tsx.bb1                     
tsx.bb0.l2:         fnmsub.s f5, f8, f6, f7, rtz              
tsx.bb0.l3:         remuw x27, x25, x26                       
tsx.bb0.l4:         fle.d x26, f8, f9                         
tsx.bb0.l5:         fcvt.lu.d x23, f6                         
tsx.bb0.l6:         jal x25, tsx.bb3                          
tsx.bb1:
tsx.bb1.l0:         andi x26, x26, 0x3f8                      
                    la x27, secret                            
                    add x26, x26, x27                         
                    fsd f9, 24(x26)                           
tsx.bb1.l1:         fcvt.lu.d x26, f7                         
tsx.bb1.l2:         lui x25, 68                               
tsx.bb1.l3:         andi x25, x25, 0x3f8                      
                    la x27, secret                            
                    add x25, x25, x27                         
                    fld f5, 8(x25)                            
tsx.bb1.l4:         andi x25, x26, 505                        
tsx.bb1.l5:         bge x27, x24, tsx.bb2                     
tsx.bb1.l6:         fmv.w.x f6, x25                           
tsx.bb1.l7:         addiw x24, x27, 974                       
tsx.bb1.l8:         andi x23, x23, 0x3f8                      
                    la x27, data2                             
                    add x23, x23, x27                         
                    amoswap.d x26, x24, (x23)                 
tsx.bb1.l9:         call fn3                                  
tsx.bb1.l10:        jal x25, tsx.bb2                          
tsx.bb2:
tsx.bb2.l0:         andi x23, x23, 0x3f8                      
                    la x26, data3                             
                    add x23, x23, x26                         
                    lr.d x25, (x23)                           
tsx.bb2.l1:         fle.d x26, f6, f8                         
tsx.bb2.l2:         ori x26, x27, 1665                        
tsx.bb2.l3:         andi x24, x24, 0x3f8                      
                    la x26, data3                             
                    add x24, x24, x26                         
                    fsd f7, 8(x24)                            
tsx.bb2.l4:         feq.d x25, f8, f9                         
tsx.bb2.l5:         andi x25, x25, 0x3f8                      
                    la x24, data6                             
                    add x25, x25, x24                         
                    amominu.d x26, x23, (x25)                 
tsx.bb2.l6:         fmsub.d f6, f9, f7, f5, rup               
tsx.bb2.l7:         and x26, x24, x23                         
tsx.bb2.l8:         fcvt.w.d x24, f6                          
tsx.bb2.l9:         bne x23, x27, tsx.bb4                     
tsx.bb3:
tsx.bb3.l0:         andi x23, x23, 0x3f8                      
                    la x27, data4                             
                    add x23, x23, x27                         
                    amoadd.d x26, x25, (x23)                  
tsx.bb3.l1:         feq.d x23, f9, f7                         
tsx.bb3.l2:         ori x26, x24, 1302                        
tsx.bb3.l3:         srliw x24, x27, 28                        
tsx.bb3.l4:         srai x25, x26, 50                         
tsx.bb3.l5:         mulhsu x27, x25, x26                      
tsx.bb3.l6:         andi x23, x23, 0x3f8                      
                    la x27, data5                             
                    add x23, x23, x27                         
                    sc.w x25, x26, (x23)                      
tsx.bb3.l7:         fadd.d f7, f8, f5, rmm                    
tsx.bb3.l8:         bgeu x26, x23, tsx.exit                   
tsx.bb4:
tsx.bb4.l0:         fcvt.w.d x26, f8                          
tsx.bb4.l1:         fcvt.s.l f9, x24                          
tsx.bb4.l2:         fcvt.wu.s x23, f9                         
tsx.bb4.l3:         call fn4                                  
tsx.bb4.l4:         andi x26, x26, 0x3f8                      
                    la x27, data0                             
                    add x26, x26, x27                         
                    amoadd.d x24, x23, (x26)                  
tsx.bb4.l5:         fcvt.lu.s x25, f5                         
tsx.bb4.l6:         bgeu x27, x24, tsx.exit                   
tsx.exit:
transient_end:
tc.bb1.l3:          fsgnjn.d f3, f2, f4                       
tc.bb1.l4:          andi x20, x20, 0x3f8                      
                    la x21, data3                             
                    add x20, x20, x21                         
                    lhu x22, 10(x20)                          
tc.bb1.l5:          andi x21, x21, 0x3f8                      
                    la x20, data1                             
                    add x21, x21, x20                         
                    lb x22, 28(x21)                           
tc.bb1.l6:          srl x18, x19, x21                         
tc.bb1.l7:          fence                                     
tc.bb1.l8:          bge x19, x20, tc.exit                     
tc.bb2:
                    spdoc_check_c
tc.bb2.l0:          fcvt.d.w f0, x20                          
tc.bb2.l1:          feq.s x19, f3, f2                         
tc.bb2.l2:          sra x21, x22, x18                         
tc.bb2.l3:          flt.s x22, f2, f1                         
tc.bb2.l4:          fnmsub.s f1, f2, f3, f4, rmm              
tc.bb2.l5:          bgeu x18, x22, tc.exit                    
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
fn0.entry.l0:       fmsub.d f5, f8, f9, f6, rmm               
fn0.entry.l1:       fcvt.s.w f9, x23                          
fn0.entry.l2:       fcvt.w.d x23, f9                          
fn0.entry.l3:       fence.i                                   
fn0.entry.l4:       fnmadd.d f9, f6, f7, f5, rne              
fn0.entry.l5:       fcvt.d.s f9, f9                           
fn0.entry.l6:       mul x23, x26, x25                         
fn0.entry.l7:       fcvt.wu.s x25, f7                         
fn0.entry.l8:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       fmadd.d f6, f9, f5, f8, rne               
fn1.entry.l1:       slli x24, x25, 24                         
fn1.entry.l2:       fmadd.d f5, f9, f6, f8, rtz               
fn1.entry.l3:       fclass.s x25, f5                          
fn1.entry.l4:       ori x26, x23, 164                         
fn1.entry.l5:       fmsub.s f8, f5, f7, f6, dyn               
fn1.entry.l6:       ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       fmin.s f6, f9, f5                         
fn2.entry.l1:       fcvt.wu.d x23, f8                         
fn2.entry.l2:       fnmsub.d f5, f6, f9, f8, dyn              
fn2.entry.l3:       fcvt.d.w f9, x24                          
fn2.entry.l4:       fclass.d x27, f5                          
fn2.entry.l5:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       fnmadd.d f7, f5, f9, f6, dyn              
fn3.entry.l1:       fcvt.s.w f6, x26                          
fn3.entry.l2:       fle.d x24, f8, f5                         
fn3.entry.l3:       fcvt.d.l f9, x27                          
fn3.entry.l4:       divu x27, x26, x25                        
fn3.entry.l5:       fsgnjn.s f9, f6, f7                       
fn3.entry.l6:       mulhsu x25, x24, x23                      
fn3.entry.l7:       ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       or x24, x25, x23                          
fn4.entry.l1:       or x23, x27, x26                          
fn4.entry.l2:       addi x25, x26, 355                        
fn4.entry.l3:       or x25, x24, x27                          
fn4.entry.l4:       fnmsub.s f8, f5, f9, f6, rmm              
fn4.entry.l5:       fcvt.l.d x26, f5                          
fn4.entry.l6:       fclass.s x27, f5                          
fn4.entry.l7:       or x23, x26, x25                          
fn4.entry.l8:       ret                                       
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
    .dword 0xce7f315145a94b56, 0x82da711adcc91e50
    .dword 0x99e85d4b93cd8832, 0xf8331c4b6b4d2bb2
    .dword 0xeb8dd3fcd66e478f, 0xe5f7e7a27c8f1b8e
    .dword 0x93f16a5f005d9c53, 0x356a937b84c73a73
    .dword 0x6ad0fa7842b2979a, 0x469afd95ab17e554
    .dword 0x3f28ee6378ac93ea, 0xed74f6c7702c9581
    .dword 0x5141f0967b682ff8, 0x87758985069a1166
    .dword 0x48530b66ddf9cab0, 0xcf49e8d585f87a1e
    .dword 0x9f483a9b8e91bdce, 0x4ead50e281ff0f10
    .dword 0xe01fc100a5373796, 0xbfe68b27e35d14b7
    .dword 0x67a465dea39bfc09, 0xb8b78d1f2f2e1aa
    .dword 0xaab70f0ecf9f77de, 0x836362cc152b1c5e
    .dword 0x7567d79c5c55263b, 0x36e8689b3ade9037
    .dword 0x8d5e6e0cf957eaa1, 0x8995fcdc7ddddf8a
    .dword 0x4839dae34bc7c602, 0x3d93171212642496
    .dword 0xd4e90a00e8ee21a6, 0xad8e532ba652b4e5
    .dword 0xf43591422c8612c0, 0xd12f900a4d5dc3d
    .dword 0xd83322062f85b65a, 0x27f00cb14c6536f9
    .dword 0x14371317ff9b61ba, 0x75595ef124e879a6
    .dword 0xd62e2cf6f8074705, 0xc8a9ed7fb94b7762
    .dword 0xab5459569a6ef7ae, 0x1d07a0a0cec8b212
    .dword 0xa9ea435fb1c1a355, 0xeb60f29629d5ca75
    .dword 0xa9d6b58c4c647a2f, 0x4a25ed0e5bdb15af
    .dword 0x53b6dd29f08390be, 0x35d37c9667a6f7e
    .dword 0xb7968b7035d696e4, 0x2f95b9b377e9a862
    .dword 0x86b1b3966d0ea5f0, 0xecda2f4d425b6adb
    .dword 0x9ec1c1b54d07c269, 0xf19475a787428a9e
    .dword 0xd0e2b895c872200f, 0xc8da0c13b6a1f3de
    .dword 0xc64eee1eb7c6e9b2, 0x7240543d1f7e16d6
    .dword 0x6134b013206e1abd, 0x835ef2057e44ebb7
    .dword 0x85eaa245d8a99a5, 0xbf49978db959195d
    .dword 0x979aca397e5da77, 0x2f83ab65958a38df
    .dword 0xae1ee16dc8c83ec1, 0xf9434ca8b6dfaeba
    .dword 0x6129237f1b6d9538, 0x7c66e4dc6cc55ef2
    .dword 0x966116a1b3158392, 0xd49d0a57eefce40c
    .dword 0x2299fc8b08465828, 0xa462715becdb1976
    .dword 0x50e2ce54cb8fb4f0, 0x121adb5f6b853ec4
    .dword 0xbfc5ad76705f3c9f, 0x6102e214a7475c23
    .dword 0x1e9097ac54d16c45, 0x88e4d9a7e4470f89
    .dword 0x4379795b18f364f7, 0x835e8c1328778609
    .dword 0xe22e2e542d866b43, 0xc73836394448a379
    .dword 0xa1f9d13d80d04dc0, 0xbf45be8dd816f1d3
    .dword 0xda442ac82862226e, 0xa64328b55b1112c6
    .dword 0xeda680b3f2c11123, 0x9c0bc6be558de80e
    .dword 0xb325ead8fe9afa6b, 0xd7fdaf371839b224
    .dword 0xf512cccc68d69f60, 0x7ead0ba1c2d5f81d
    .dword 0x480c6b0ddd0bbacb, 0x74381700c3b1813a
    .dword 0x7b63313fd173db03, 0x8d036327b886a397
    .dword 0xc3a8951e2a94fa0a, 0xcd223fcb9e313594
    .dword 0x595f1e8e5b81a42b, 0xa952dc7fe54813ca
    .dword 0xf129ab4f7cfd0b7c, 0xef649e7b4782cb27
    .dword 0x7354712c326a9f48, 0x9347f3e081d034e
    .dword 0x2f637901a0595837, 0x76bb2af203cbf31b
    .dword 0x160314fedf87e425, 0xac04945ec7c2439c
    .dword 0x728e4304f8bca683, 0x23f6a8820bdb6d3
    .dword 0xdc21d58da642aff3, 0x4f285035122be928
    .dword 0x8f9b3e0d6e002af, 0xdafe6bbdd5a064dd
    .dword 0x7e2a196d8e9be741, 0x94a8d7e06e5a4d2e
    .dword 0x944fd942fbf9ce91, 0xbf9d3b3c2a28544e
    .dword 0x431cbceaa1d71997, 0x34c06245003418
    .dword 0xd8f82b499f4c8ff4, 0x1a8dcd4feca0c9
    .dword 0x29a8b765f1324c11, 0x99854ec7ec5da83d
    .dword 0x3d416d34216a5836, 0xe223fc2b50e3f473
    .dword 0xfa958bb7ea219216, 0xfa551bc2a12fe316

    .align 12
data1:
    .dword 0xb827b03ffa7a7893, 0xc937c75a74ca251a
    .dword 0x501f0f22b39b5b44, 0xc6a16de1200df9dd
    .dword 0x98559e356e9e71f1, 0xd920d315623136a2
    .dword 0xf2b4377483335621, 0xe224c4a7002aebc0
    .dword 0xa19dc336e0699943, 0xe24e710b40c7f5c1
    .dword 0x45b5110b8328cb7b, 0x2be00866adec680b
    .dword 0xe28ad2e39b53ff00, 0xf3675f9cb75366fe
    .dword 0x597b9e28a44da6ed, 0x87e9136a02684629
    .dword 0x83a400f6bf2a2c91, 0xe6ed8c46a567edbd
    .dword 0x644b1cff02492292, 0x2f7519b1e39cee47
    .dword 0x1230e0bd50ad4729, 0xf66f1fd5faf6f0ee
    .dword 0x2b52d3fde35c3062, 0x40487a2685c0fa01
    .dword 0x987029e0eb8d024d, 0x34fa54d2a78f374f
    .dword 0x4ccdd195da98457a, 0xc40e2a0deab3f05f
    .dword 0x827074ae3d156a60, 0xb14836bc5a776727
    .dword 0x995f47a3535914b3, 0x3b5e71920478c8d6
    .dword 0xe45439c1e5fbafb9, 0x84b103ea39d1f618
    .dword 0xd9aba03dbad605cd, 0xdf296bc5732bd229
    .dword 0x456a455d64477d66, 0x8ebd28a908970b0b
    .dword 0xba1002e593dd40aa, 0x90ce59c92d949522
    .dword 0xf68da8c4aab86a5b, 0x24f86f40acf2c2c0
    .dword 0xe15a21d13c1b54ad, 0xa75827564a7635c8
    .dword 0x606f8428be309247, 0xee3cea6b7d5ec698
    .dword 0xe37a0313beed7b88, 0x6de0c5b3c3797469
    .dword 0x8405f5badd346c76, 0x4363c03ecda49416
    .dword 0xc489eaf43d9e9513, 0xbdc4e8b5826a7124
    .dword 0x3148d544a9720e65, 0xf4b7509b72a5723f
    .dword 0x158b4ac0b71b1949, 0xf494b35142b5fc04
    .dword 0x1cc0dce57d4ff45b, 0x6d897c20cd996a34
    .dword 0xac4d106ce635c1, 0xbbf897b5d86331c2
    .dword 0xbb1d00afdd704673, 0x704890125acf8905
    .dword 0xe23a991421dbb5a1, 0x1e90cf5551ecee53
    .dword 0x966ff3fd4eed3d5d, 0xad7d1434ac34f886
    .dword 0xc9d92f9356595b1e, 0x18d510f467c0a410
    .dword 0xf83aab6d36453e12, 0x53482bef424839f1
    .dword 0xa383799ecb775f99, 0xee23344d126e9f24
    .dword 0x923733bbe90d0344, 0xd26fadd1f8e8e902
    .dword 0xb59b878bf23f64aa, 0xdd8d68eace9c806e
    .dword 0x420cb469c55b87d, 0x29e05a78be7bb821
    .dword 0xdcc57b787885b843, 0x5f970beaaf546815
    .dword 0x1f7bd1c92a8fc3bf, 0xd93ca37da79a53f1
    .dword 0x13da56761bb318a4, 0x8a8213bc5ceea4a1
    .dword 0x973fe8a4952c6f60, 0x52217380b1c4c1a5
    .dword 0xbdd3d463d6a0a4dc, 0xe0f0ee5bb3f4dd44
    .dword 0xfb121f7baa1f5984, 0xd073bf613949a08b
    .dword 0x2f772bbc8a2a642d, 0xa3f14900ad10d0b4
    .dword 0x886d309bbb6cdcf2, 0x2516abc5060a6647
    .dword 0x6d7bf49d2040c995, 0x4fa38808104c1b6a
    .dword 0xedb78cb24a259144, 0x66ba4ecc63d0f6ae
    .dword 0x3a20825c69d216e5, 0xc3f20570539bb4b0
    .dword 0x926bb06f47589950, 0x9a4d956ebd538e36
    .dword 0xb42515b403a6fa67, 0x7913c5fa38be0f3c
    .dword 0x499a62e25db51294, 0xa16c62612378bba
    .dword 0x75c694a2f8f64b8, 0x796f998a4b73b6d1
    .dword 0x7273cfdd91c24561, 0xfaae7a99e8e3ae04
    .dword 0x3351a314c97b811a, 0x88894855efca34df
    .dword 0xe26f3c4a740a6e37, 0x9537078a64c05296
    .dword 0x1070c1e62bbf60de, 0x856e7da234de935b
    .dword 0xdac79a3b8a404a16, 0xc4a0c4dc3a5ec04
    .dword 0x200e82e7d467af1e, 0x521c6e46662f3466
    .dword 0x9bc1d43e98c8d3da, 0xdbda20f03f347c87
    .dword 0x21dd5a1da0487f5a, 0x31a209f34ffcf3a5
    .dword 0x7d9bdb8545f09593, 0x7c3f37ac10b19a57
    .dword 0x44cc2cc1a8a8bc64, 0xe025716d61d36a75

    .align 12
data2:
    .dword 0xd766647ede08b554, 0x6a7177ddf5e7b2af
    .dword 0xf412961ef3e142e7, 0x7b4af9daab79360f
    .dword 0xf69df58a3325cd9d, 0x52511681a069fe20
    .dword 0xb05c6304f4922f85, 0xfbaeef633b4ad481
    .dword 0x21a03c47b2f0e34e, 0x3f9ddbf672828bd2
    .dword 0xbd6817ca081fe21, 0xc178c2a5aec85fda
    .dword 0xaca82308f6bc9325, 0x582b53350e042149
    .dword 0x3849233c8b48d880, 0x2621e567e1b6182
    .dword 0x5dad315c998b72df, 0xdfc626a673b87c10
    .dword 0xbfab3996a0327d0a, 0xf220f03b3243a529
    .dword 0x31d9c5a7157d069e, 0xaca3c92efd75ff69
    .dword 0x243bc3861b9bc5ad, 0x634a657d2c559da8
    .dword 0x2c3f3973d448c621, 0x104f9adb3b063321
    .dword 0x39300e0a228bc3ef, 0xc8b4ba1af22d0957
    .dword 0xe3486332796a47d1, 0x7bef6c5337a11bc0
    .dword 0x59329d8348cb2c46, 0x700d23cb261edcaa
    .dword 0xa0d2d609b9932e90, 0xd2177246e8b5ce81
    .dword 0x842936a93fbcdab4, 0xf0241af87a19589c
    .dword 0x529e61ceb766b029, 0xa698188c01b83f74
    .dword 0xf196e6de37e7bd9b, 0xf487e8721998740c
    .dword 0xf185e6f3ada38720, 0x8757762598fc6c29
    .dword 0x5dd8ddaac58692c7, 0x3f3077c11beb906e
    .dword 0xbe30dcb786b26e6a, 0xdcbc0749f80b97e
    .dword 0xe54d4c4b3a2fa87a, 0x4689b5ba8bfff331
    .dword 0x3b1469672751f699, 0x804befe4811be0b4
    .dword 0xe2213b5f3a0c8941, 0xa70590374521eb7
    .dword 0xc13acb867603d060, 0x312e48ed02bb155c
    .dword 0x9e23c0def24721b4, 0x42c7dd9d50939d82
    .dword 0xd9236a210937f5b7, 0xe780be3cb3db229
    .dword 0xfe053c73c774e618, 0x7fe094fd0b2e1238
    .dword 0xea2319ca31288434, 0xd30f101a35c87c23
    .dword 0x943005b31168c6b5, 0x146c46931120abc9
    .dword 0xd1acc08b2eba5657, 0xd828363df1f6ea3c
    .dword 0x9fc5e6c2943b96f, 0xaa07b6c93c73422
    .dword 0xdf3b745005922aa0, 0x780258a79a3b6596
    .dword 0x8c929835189e5f58, 0x17ec2527a4fe6f9a
    .dword 0xf45a9cced158233a, 0x975408612d47ee65
    .dword 0x8d9ef287fff52ef9, 0xc45d6e3dcb566be8
    .dword 0x1b876cb28fd56edc, 0xdff1802ecb7bb83b
    .dword 0x17be73e707e6d451, 0xe177c510dcd9a213
    .dword 0xcdfc3e5c58dfbc27, 0xa8464eb8b7c95ece
    .dword 0x871a003e1f3b5454, 0xef118858751fdca2
    .dword 0x949ae38435d212bc, 0xabc26f55db744d4a
    .dword 0xfd48516b99f8b77, 0xf5a5134253a86937
    .dword 0x6cb8647564a23210, 0xff08609834485341
    .dword 0xd5830ea680ecf0f6, 0x5eb6d545cd29341f
    .dword 0x4cfb4cdd7675b5fa, 0x6f06960f86c94b08
    .dword 0x2e3b0f7033e005e2, 0x78d342e98e951c6d
    .dword 0x88e3feb794bc596a, 0x61e629242dbd6e26
    .dword 0x39e23080c13a1f3a, 0x7bdbcb72f2dc0b8c
    .dword 0x9dd42bf77823ff22, 0xaacd4f80e7cdd6da
    .dword 0xcc2ea6c24485e0b6, 0x9ec2c5dbba7cfe1
    .dword 0xcc58b341171bed25, 0x30763b9a3315bbb9
    .dword 0x416af46152c16f3b, 0xe4fbdf6e6e59009d
    .dword 0xf1e1504fc9c73626, 0xe1c20d335e066888
    .dword 0x6024d4aa6fbaf048, 0x21caeec21618a7fe
    .dword 0xf03611f6e6e3a41e, 0xf6321b66a2e8b9ea
    .dword 0xb4d8df4ea5b16a73, 0xbca53aae400d13e5
    .dword 0xc90d000de49c0b95, 0xc1831dc52386d8c0
    .dword 0x97f8afef62f865f, 0x4fb2ca6c2e3be155
    .dword 0x8af571d536d601cc, 0xaaa02412d575443e
    .dword 0xa8294f082027424b, 0x10408a3c140cf872
    .dword 0x6054592853c719e6, 0x452a4873fe0004a6
    .dword 0x2db4eddf5b3460f1, 0xe8ffd4c2f5c329b3

    .align 12
data3:
    .dword 0x8b68a68656bfd898, 0x816ed9b07cd99551
    .dword 0xbe89700b9294b140, 0x1d9fc8b22388433
    .dword 0xc25999a4c337fc5b, 0x9fe50e6f3c381a4a
    .dword 0xfbe8c564eb1ea812, 0x2ac87378d4f73fd6
    .dword 0xdf4360b762bfa728, 0x89c30cc8982da2c4
    .dword 0xd3170d1523c594ed, 0x4cbab0a082170bd
    .dword 0xc4570b93c32564b5, 0xdffcccfd7c9d26c5
    .dword 0x13af48e0d72b1f55, 0x16d84f96beba6bb0
    .dword 0x94d10ff43a49d517, 0x891cb845c68f7a98
    .dword 0xe4aaaf5c6828fce9, 0xbc162c419d552fcb
    .dword 0x6f55454affb85106, 0x1a9a30a8462329a2
    .dword 0x82cfd0d42f2549b8, 0x4848e32a9b8a1ee9
    .dword 0xcaf227448f40b74d, 0x92c74a89203e142c
    .dword 0xd2b9801cbc2f351a, 0xce938cac67adddb3
    .dword 0x2c0159f50cda100b, 0xc10f2e8a2ab9d4d7
    .dword 0x5d942dc18c140bf6, 0xc43ee6e6945ac992
    .dword 0xa41781b9ed3487d0, 0xe9125c333c2ef4c6
    .dword 0x321b4ff8fcfa342, 0x7f776d419af5fcd2
    .dword 0xeeaacb70230235c, 0x7fb652aa6f72409e
    .dword 0xc22fd228fbd24d5e, 0x15d7106f10d9a486
    .dword 0xa2889f6d7240294f, 0xbfe7371abc7f8fc2
    .dword 0xd2cf6b983dfe83, 0x412a4ecbed59a146
    .dword 0xff930ed7ff49c471, 0x69ebbc7d51a6fad7
    .dword 0x5dfbe77ce0ed424c, 0x6f7e9e5490e7dc37
    .dword 0x84dbe3c0f1b1c0d5, 0x3e303e97115246e3
    .dword 0xd7e8f03a769fd04c, 0xf547f55ecb1fc63c
    .dword 0xe2a2d76f0ccebe4e, 0x57eb551c253680e3
    .dword 0xdc71c9adca6cbf4a, 0x4dbedfcc6e3b7738
    .dword 0x752469ee0287ae9d, 0xde22cfdae4ec7925
    .dword 0xbd87b42bf87f44ae, 0x5f81f87895d989be
    .dword 0x8302391a4df7e0f2, 0x1c6d58c8a6dcee0a
    .dword 0xbbce10d0cdabe7cf, 0xb90895e2ff074024
    .dword 0xa6ec3e98ea47a54a, 0xd0dedcc5d5121bf5
    .dword 0xf959785f2cf12b68, 0x19dec317a5b63f17
    .dword 0x37bbc909cb11b306, 0x1eb86db2d7b3081b
    .dword 0x624c9f1d059c9279, 0xd44d1cba4b923544
    .dword 0xea7e70639f93fc04, 0xbd22c5d4dcb8cf29
    .dword 0x7407ed3fc34fd22d, 0xee0af6d50b48fff7
    .dword 0x4e5e9227703ce292, 0xc5cb6c18dd5f7b03
    .dword 0x9f13e45258d9d412, 0x343a3c701efa3b3f
    .dword 0x52afbadbd9d3922c, 0xc2e4f16bfb1b573f
    .dword 0x31955309e06956a, 0x183adb4cf6804dd
    .dword 0xd1eb7e125df2ae92, 0xa64090136fdad790
    .dword 0x9b0cd2152c4e91, 0x6515c4828d6a1490
    .dword 0x96d8e9308595a64, 0xaa6597abac5ade52
    .dword 0x2a35a95ba3aced15, 0x3f6459c22c46c4b6
    .dword 0xcb26408f7227693c, 0x7928f3769a347ee9
    .dword 0x5868df40158045c8, 0x2df7d2583eb44883
    .dword 0xa103dbb68ef8c7c3, 0xf72b1d83dc52110
    .dword 0x17073443767a951d, 0xadbed7f9b524727a
    .dword 0x7858586ecd8333d3, 0xb60a195a0da329fc
    .dword 0xdec63bf89e71d30e, 0xa6ec866d98363846
    .dword 0x30ddc348f965fb70, 0xe8fd82c91213a8b4
    .dword 0x15f847bd9071bb09, 0x7108cc1c4c406ba1
    .dword 0x14aa2eb2026e115e, 0x835326102be97907
    .dword 0xa94d06aa6b13e1b8, 0x13b4063654bc814d
    .dword 0xad5451f6b207dc1, 0xb743348db084070a
    .dword 0x43866417db5ff2b9, 0xcb6d7e90b35d7ab8
    .dword 0xe7e2aa78dc31c77c, 0xd387c4507511be03
    .dword 0x8744ce00b7e99f5e, 0x4cdaae1d0de0a0b8
    .dword 0x77e90ecdfa5beafb, 0x797085b7ec142d66
    .dword 0x5c24dd053d4c932, 0xec251e7f57a6e1c5
    .dword 0x726d479c6969fef5, 0x768205eab1e7ffa9
    .dword 0x736cfe9d8c3c6188, 0x78556a6d0d5ca94b

    .align 12
data4:
    .dword 0x96b6c265f3be3090, 0x4cef4813b1c44937
    .dword 0x4e8f7c97f446e0ec, 0x7b73cee2b1b30531
    .dword 0xa81f79ae91cacd53, 0x34833b3bd69209b6
    .dword 0x5ef470b1e13fbcb6, 0xa37bb61f7fd8f41e
    .dword 0x1d9381a12a900c8a, 0x407d2ca7b4f358b7
    .dword 0xf15299c27f81388c, 0x3cd2145be11d6141
    .dword 0xc99e44e506e0f754, 0xc73772864f105a70
    .dword 0x67fa650b1c9bcffa, 0xae95d5acd3bb9ff8
    .dword 0x9be304fbd4054877, 0xcea06249ea708fe6
    .dword 0x702a3680d8ec718a, 0x9bc64a492fe63fd1
    .dword 0xa39e6e2ef6e6e334, 0xc2a6c9d73353d5d3
    .dword 0x74d9245c587183ce, 0xaa16eb7a66d3e522
    .dword 0x9f46f4e3e7e88fd7, 0xe27a2a152b604cb4
    .dword 0x9e668aa0b4f32a0d, 0xf3a7b252b4030d2b
    .dword 0x99522eed935d0c20, 0x57335eee976262ba
    .dword 0xb5f801ae43a7148f, 0xe70ed6ed13fb61a0
    .dword 0xaf7d4520ac9aefd6, 0xa1417c0b994322d4
    .dword 0x4a0b16663323cbb1, 0xa30219438acecd02
    .dword 0x3d3186c15d1b5e8e, 0x13dfb2891c8e455
    .dword 0xf241e0d327bc5278, 0x103ff1d30aef558
    .dword 0x9c946603448203af, 0x6d8c8641d9d263d6
    .dword 0x32d7e762ac11a6c7, 0xd7ef9048691f4ed8
    .dword 0x73d6de9d05239f6c, 0x5757a9525f0cad2b
    .dword 0x17d670ec2b723ecd, 0xb1bfb6524ff33ac2
    .dword 0xfd1306c6ee54f40e, 0xbcb9693e391c86e4
    .dword 0xf58675b3934c02fa, 0xafb5351c6b704eb7
    .dword 0xb64af92ed5b3cf73, 0x8f52e2ae88e7fb89
    .dword 0xec66e27c41600467, 0x4ebab3470f133827
    .dword 0x952e0e7b8442a223, 0xc36f53d08c96776d
    .dword 0xcaa234397f03cc5b, 0xe36e7de264deed6a
    .dword 0x96b5c5be8e36a140, 0x7500830bef5459ea
    .dword 0x70d5648ab9ee2b9, 0xf6c1d1dce6ca29dc
    .dword 0x7798fe3c01e0c2eb, 0x5935a588b5a96ee3
    .dword 0x1e500119e5bed169, 0x467498afe6c1a97a
    .dword 0x426f01c3b6077fc9, 0x9a315be2b796c746
    .dword 0x88b8fc681f64f4f6, 0x397b635946d63185
    .dword 0x9f51dfce3c12459a, 0xe476c617dbfdceef
    .dword 0xfe216d6e0e6c23b4, 0xb79c6f199ea7e5f6
    .dword 0x47cfa13c7bd25e55, 0x3a8822e7f170a790
    .dword 0x90206907cb7b93f0, 0x9d8a8d1025171b57
    .dword 0xe094ce088dcc8cb5, 0xdcf930af3e88e9fb
    .dword 0x20fa0aaf488eff9f, 0x7d073be0cd52147c
    .dword 0x4b9e9f49a36098f2, 0xe60869657d8ce9b5
    .dword 0x457de56e7b701f7e, 0x70667d7e5c967e4
    .dword 0xb53cbcfd3bb02fa9, 0x947b5d275ae95d1f
    .dword 0xe0f74e88e63512a9, 0x9f98bc27b559bd87
    .dword 0xdf5f17196f096908, 0x1c5b19cf567720e0
    .dword 0x3d7f8bfde6ad9538, 0x5a1d9f1c52f1cae4
    .dword 0x525045e34702023b, 0xbee361094a1055c8
    .dword 0xc71ce7415f31951a, 0x953ff43e150c2de6
    .dword 0xda418a670e6e39e2, 0x2363de6ba49c411
    .dword 0x1846f3156c7a97cb, 0x36c98a424bd0a3af
    .dword 0xc071631f55bdf194, 0x7a4ecee055a71bf2
    .dword 0x6dfae6e94f1cc3e7, 0xeac2c124c7915d42
    .dword 0x36305c7710a81fb4, 0xf6ab31aa7064730b
    .dword 0x36bb7333dae27b00, 0x48c900438da5e7dc
    .dword 0xb28becb9d80f4938, 0xce97c0f000aec230
    .dword 0xe3b517e2c793cbb9, 0x1bee0137af74b659
    .dword 0xcd06d8ea87d5d4dc, 0xdbb8e9f78e7c6929
    .dword 0x6b6d8e1557e0c82a, 0x4e9c0c864ac10f6a
    .dword 0x116fcf74691f5117, 0xf0278669e80fe2da
    .dword 0xb097610aa7f8220d, 0x746b5ad93324346c
    .dword 0x456cdb89dcc317bd, 0xa7f728002ddca5e3
    .dword 0x59f776f00dcf22d4, 0x46091defae60a43b

    .align 12
data5:
    .dword 0x91da0097fb5721c3, 0xe02a28823d77a159
    .dword 0x58d6871d5cadf59a, 0xa85d7505d03e621d
    .dword 0x26c92361180508f5, 0x686c3fab50f185c7
    .dword 0x218afe75f8e6ba27, 0x5ed74707d0338e6e
    .dword 0xa1fdca80d7528b6e, 0xab0c29d544c13d93
    .dword 0xccfd05be96c04d2a, 0x650985e50ed1cea5
    .dword 0x44699c19d2e65315, 0xc386327ba7256e3f
    .dword 0xe4c14a880b6dd60, 0x1f84e2131938df23
    .dword 0x92e78f3c08d4821c, 0xb030b65c8e03482
    .dword 0xaff09252ca2187c5, 0xffaaf2c15a4e1dfe
    .dword 0x927068bc4f19af85, 0x245f32cd4c5fd108
    .dword 0x26c31baf47cc9d4, 0x17d5218c42c36f8a
    .dword 0x5d8aa244d437f10c, 0x3ec4228c079a4378
    .dword 0xb86b2eadbace85e8, 0x8758c74f4685974f
    .dword 0xa101119aef66e552, 0xa7a37d2b4e2cd03
    .dword 0x72ce10be9cb8346d, 0xb41d2a0af05a9bf1
    .dword 0x16ff8831527467f9, 0x25e3771c4c073870
    .dword 0xdb2cd3adc1a5347d, 0xb66daa7640b24dea
    .dword 0xeeb5132c6c6dc007, 0x7f6285cd6481e2ca
    .dword 0x14dce6a75f5465bd, 0xc2bef11a885201b8
    .dword 0xd3845675d0b03982, 0x4ecd02e04ca1581b
    .dword 0x1f639fd0ff1b68f4, 0xe7e2f72e63ff766f
    .dword 0x703b8e6b726168d6, 0x1bc9eb0b8d97fa5
    .dword 0x8b9400a4384fa811, 0xd7c0d9a51a1213ec
    .dword 0x86afa48c94fad585, 0x626070dc278fed81
    .dword 0x85c8ad3b1afc617d, 0x1b40e54b1bfe7a0c
    .dword 0x3393e5ea01d68c22, 0xf7f4006902f7771f
    .dword 0xbbfe2a5a66ebabb4, 0x1c113af6207e5538
    .dword 0x53a97e65c9d8bfc1, 0xd2c1d74b318f913
    .dword 0xb1a68c0d99103966, 0xf0f75a9081c7122d
    .dword 0x6680de41f959a83f, 0x9a37c424b243e3b1
    .dword 0x33d021a97fe88ff0, 0xac00a06579b678e8
    .dword 0x530b47d338d50ff1, 0x6f1a07fec46493f0
    .dword 0x66137c2a0e55e88f, 0x17f2789e0663d9d2
    .dword 0x5ea521094033b9c4, 0xb5996ec54d810f24
    .dword 0x2451623651a475ef, 0x9c48d75ad1ce1f68
    .dword 0x1cc090c766da3aec, 0xe7707d115d55d161
    .dword 0x1bf38c3dc30ff2df, 0x831148011f87d6b4
    .dword 0x4e7366eaddeaef05, 0xe13a95f6be8effb2
    .dword 0x58c378026ba2d690, 0xfd3ede57988a0ccc
    .dword 0x4ee1f47052894094, 0xc41bb0afb5210231
    .dword 0x31fb1b81b5d655ba, 0x2fe40e6c7f1457c4
    .dword 0x8c5f43b76c50537c, 0xff354958bbba7fb2
    .dword 0xee66ac7d0e0d9ba0, 0xcbe5b8b87997cdb1
    .dword 0xb0014e29efdb6692, 0x3f0e377a330186e0
    .dword 0x1ee4dbf5cf02b2b, 0xf6ef1e91b73f632d
    .dword 0x86c38682021c0cb3, 0x620a327ad5a9caa1
    .dword 0x71cfbfbe28da633d, 0x12d5d6359ca403a6
    .dword 0xe54c87abc00e1537, 0x5d579e91c3df5d10
    .dword 0xfe5f3b63d4b83d72, 0x7887358997232db
    .dword 0x4cfdfbc9582a5a5f, 0x7b308c4d479de03c
    .dword 0x7d3ff6e1e2476f40, 0x55504ed481ee1ca2
    .dword 0x94283a09b5a029f5, 0xcb22ebe55dbe06a1
    .dword 0xf3a6f330a1e82c7a, 0x2a206fe4f4e4088e
    .dword 0x271293e575cbaace, 0x2d46aac5b89ae935
    .dword 0x302e57dd061978d9, 0x712801b89f6a131f
    .dword 0xe48c692c52191486, 0x5d57a6b8aa7e3136
    .dword 0x6c1df998ac4a93c9, 0x5044ef19b81a133
    .dword 0x41ab20c513d83895, 0xdc1de19ef5e0bbe4
    .dword 0x5c9160b128aa308, 0xe0075cee936d7652
    .dword 0xdad981f07be7a8f, 0xb02649a3411f556d
    .dword 0xa48eb95c33bb2c8c, 0x27f32fedec5890a
    .dword 0x1681ea7262de191a, 0x63be959969440c8d
    .dword 0x3bbb259982ddab02, 0xc0899110cec6f86c

    .align 12
data6:
    .dword 0x8a153b9cbdae3f04, 0x93af2c3dbd18fe50
    .dword 0xda55b02ad1179ccc, 0xdc2dde3fc6486ef9
    .dword 0x5b6b0d2e6289720f, 0x1ff540ae8da7085
    .dword 0x91c4bacfb113202a, 0x816b3fb1c8eeffd0
    .dword 0xd57be5753e98601f, 0x38213185d7922c1c
    .dword 0x1e0d8997d6647b64, 0x984b4e7513f2c63b
    .dword 0xe853940d29f93f89, 0xd4d32d660b62873d
    .dword 0x83fdb608a55301d1, 0x82ad514a57c5e7ef
    .dword 0xcd30fa5f1d2bb901, 0xfb0cd4ab8c81be47
    .dword 0x84c07cc50dd5263f, 0x6f24f0d76c7dc1b8
    .dword 0x836e39f9809bbeff, 0xbbcc5b08476a3c5
    .dword 0x48bb3e3ac31e1519, 0x7fb4034cbbec8f70
    .dword 0x9f821e6837137ffc, 0xb068b959902eb61f
    .dword 0xc9ecfdf7dec99394, 0xa708a111b589783b
    .dword 0x2b2a3c47ebbeb7cf, 0x820449139d3516e7
    .dword 0x634c15bacfb95b67, 0xc3f6f54d4da2e455
    .dword 0x7f00c939366cf88f, 0x2b28bef751812fd
    .dword 0xdfce47c3d47d32f7, 0x1af1305ced6c6c6c
    .dword 0xd3252e8ced43558b, 0x2b7af1f46eaadca9
    .dword 0xca067c43abf77e5a, 0xf701e81408b9cd04
    .dword 0xea76de517c8db647, 0xd2916859176a593f
    .dword 0xa2224af8c81de7a3, 0xb058a7216d1653d7
    .dword 0xb74d6523794debe3, 0x585a96116837c3ef
    .dword 0x7e2da4745a764da9, 0x20956ae36fa831ca
    .dword 0xb1985613d3910ce3, 0xbda179ea0a6bb648
    .dword 0x9e2d32f756f6898, 0xc227db31c2b7fac8
    .dword 0x739cfdf048844b49, 0xdaf80628c4b88b9e
    .dword 0x45d774041b50c871, 0x9a24d0548d79d6d9
    .dword 0xc260b2110fea24f4, 0xb4003de6ece8c6c
    .dword 0x2fda5a2fc94f626a, 0xb25fec9b8731b9c4
    .dword 0xee4ecff3a0159a9b, 0x85a3174ab0bf1d4e
    .dword 0xdd36c0a57f6e0652, 0x8562311d2fe9bfdc
    .dword 0xf784db27da4486aa, 0x5af3eb32265e4eae
    .dword 0x668ef4a7d958ea72, 0x7a5e439bde4ee210
    .dword 0x60828582f6163226, 0x7784f13fdab823df
    .dword 0x24bb733c16c1f614, 0xea60c41f0ae031df
    .dword 0x3e2247d945501aad, 0x4a6b1a32a2eb0f84
    .dword 0x79c4ab8d3854c6e9, 0x64551ba57cdbf78f
    .dword 0xc5f64404023df1e5, 0x84a7ccd239340f95
    .dword 0x64087e46fc742fbb, 0x2707bc481a5f4a81
    .dword 0x154d1f0cbde9a3a1, 0x2054388c223bd88c
    .dword 0x3736c6dacdc7fcbf, 0x1a07b7aede376694
    .dword 0x8cf4b9f30135c8ed, 0xf8315fc26eb53a99
    .dword 0xb7a47107011239c, 0x6c0247e907800e76
    .dword 0xb150af9a3cbc4bf9, 0xbb57e9aa5b744920
    .dword 0x85454c56f9ddaba3, 0x7b675d28f95fbbff
    .dword 0xdc15ba4c1ffec04c, 0x3162d6ee4725192
    .dword 0xd0ef43a1f3abf342, 0x73bdc6bee887ef1b
    .dword 0x17b3532bcbdb7969, 0xeaeb75c0f92d8347
    .dword 0xf264505ebf82fd59, 0xb7fc274ea82921d3
    .dword 0xe9266a437c96c357, 0xdcb681aa25869ff5
    .dword 0x856931d8549d498d, 0x626909dbde858686
    .dword 0x5eb7877baa5fc090, 0x9c5d908c4c544feb
    .dword 0x5703097e63f28792, 0x41156d08cc2c6393
    .dword 0xdda1001b59be69f, 0x86deb7dfd98da37
    .dword 0x23b951c840b77dcf, 0x76f16b3df6743f79
    .dword 0xef3cef84f65294c5, 0xe65d517150afdfd5
    .dword 0xf599b7c994a8080a, 0x79565d646052bcbd
    .dword 0x308a662eed9d77b2, 0xa1bd814d0c2c0a59
    .dword 0x57362ada8d37df04, 0x3a873e640439a2b2
    .dword 0xc5348cc1e0b234e, 0x6aeb957af3310dac
    .dword 0x4e0fa61d02037a6a, 0x56cdf568d99d970b
    .dword 0xd56dc1dd1c370480, 0x158c9ee1bd65a0e9
    .dword 0xec9e15528023df02, 0x7734f99f1f1bfad8

    .align 12
data7:
    .dword 0x7f993b36282fb483, 0x7c1f50006756ad3e
    .dword 0x9830bc677a488183, 0x8140624cc4b1a664
    .dword 0x8761c93ffd76b157, 0xfb14eeac632f3930
    .dword 0xb9bab01d4cc85c52, 0x5919956d67eff7a
    .dword 0xd04021cbd3b7ad4b, 0x67c9b5c6c0c3146a
    .dword 0x698da313a7f93e2, 0x2fcc77f393c977fb
    .dword 0x78b495dcc25b4111, 0xa8e34388d2c1c613
    .dword 0x7656a311c5190b8f, 0x96614521e475d535
    .dword 0x47cef390c936435c, 0x8d6ad30e5eca0f73
    .dword 0x1e38d8544b598525, 0x4785fe14cd050a16
    .dword 0x8e455451257faa9a, 0x4253baef2f191b30
    .dword 0xdeb5176162341748, 0x2f65b2525fc9e655
    .dword 0xc751b33920c443e2, 0x8e9bba6e9aabfec3
    .dword 0xfa591263de25e88c, 0x1b07d1e91028ccb5
    .dword 0xfe4bb210cd56a7e, 0x46426d3313450a8c
    .dword 0xd5257d970e732820, 0xd2745b2d7215fdaa
    .dword 0x1c33a41b1d860a6f, 0x363b95bc00f0f91f
    .dword 0xa516587e201d2854, 0x972d33d143c41a1a
    .dword 0x2793bf5010a825f9, 0x6a8752058e68e304
    .dword 0x3fd7f85b6362f1e3, 0x6de582a6c6e528f1
    .dword 0xc0530dd031919fcd, 0x2f9b50da009b698b
    .dword 0xd26a358098242bc8, 0xa7e5d3114523f353
    .dword 0xa0e8b74e797e035f, 0xea03530a7921b081
    .dword 0xca72f5b76692a1f7, 0x9a32e971802eac4f
    .dword 0xfbbeb0af7af30852, 0xc10d75ffb941aea8
    .dword 0x627001bbf4bec349, 0xad62fd1f5be1fbdc
    .dword 0xec3852507565829e, 0x9bf840efb64319bf
    .dword 0xad8d83204444cf0f, 0xd43f87f0e0d26525
    .dword 0x449562b13f6af5e7, 0xad55ba13ef459579
    .dword 0xbc8adf3c7556af29, 0x3fb3d35b67eddfa0
    .dword 0x1b38e94187861bea, 0xa8e9063568d4a4b0
    .dword 0x2b2f08e676617868, 0x800545436e80e188
    .dword 0xf62f1781f7258c8b, 0x880bf0a1bd155f1c
    .dword 0x46be3f4437f2f3ef, 0x3a6fcfa758d30611
    .dword 0x141b755eb263882d, 0x49e025ebe3c4db22
    .dword 0xada4778a6ce03208, 0x800a0fea571540e
    .dword 0x4609ec9c0c9cf4cf, 0x9de47002c00d4f91
    .dword 0x6c8ed35f47cd390a, 0x8869b73b2e4142c7
    .dword 0x776a1d7145c81a77, 0x84cae3989b9a9c34
    .dword 0x5339eb32f8d26a66, 0xa1becb46c4e781c4
    .dword 0x9cb22f4adf99d754, 0x19f98f9f2f1f2a15
    .dword 0x398a75d59ad09248, 0x60acd889999e9f9
    .dword 0x41bfa0d1f3618937, 0x2df8e2085a6196da
    .dword 0x819758a81ff9fc58, 0xc34d9969bdee37a2
    .dword 0xa252e0f9db153d78, 0x61a200aba10a7bb5
    .dword 0xa9fb69ec5b4eef29, 0x38ea9bcec4825976
    .dword 0x72bc50b0e4028286, 0x403cc3bd1bf3258f
    .dword 0x64438573fe6016e5, 0xc892cee61db216dd
    .dword 0x4fe5c33276bda5a1, 0xef0fac7a33f3f0b0
    .dword 0x72388dad04adc796, 0x59efd4a768b7a66c
    .dword 0x73920fa0148d6f69, 0xa655857fd66f9034
    .dword 0x4f5a1d41c7f20c04, 0xde0b32cf1f933ab9
    .dword 0x32eac9c0b42c0357, 0x4576259106e15a39
    .dword 0x408d6262c9483c43, 0xad844ba9bd512913
    .dword 0x8f3cd322ee1bb73e, 0xaa1a74a487daa9
    .dword 0xc373d7f29ff51e42, 0x8aaef2a62a4d67fc
    .dword 0x4d457a0d9e4dc8cb, 0x90b5c7c54c3c6c2e
    .dword 0x513fd8a76ecf1319, 0xcdddc812a30f668d
    .dword 0x5daa467b6f304b35, 0x720c5efa5aaa1bed
    .dword 0xc5374c0e5329ab39, 0x538f1b2e267364e1
    .dword 0x48596db59634d5b, 0x7d8370f446d6252c
    .dword 0x4a7831fd38d63b1a, 0xcd23ba85bce04af8
    .dword 0x45bda431d30e1449, 0xcd07d23c6fa2838d
    .dword 0xea712ac0e17d872b, 0xeec5bdacbc79bbf6


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
