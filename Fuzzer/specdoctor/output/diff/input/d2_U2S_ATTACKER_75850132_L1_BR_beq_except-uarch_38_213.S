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
                    la x19, data5                             
                    add x21, x21, x19                         
                    fld f0, 8(x21)                            
pfx.bb0.l1:         andi x21, x21, 0x3f8                      
                    la x20, data4                             
                    add x21, x21, x20                         
                    fld f1, 0(x21)                            
pfx.bb0.l2:         andi x21, x21, 0x3f8                      
                    la x18, data0                             
                    add x21, x21, x18                         
                    fld f2, 8(x21)                            
pfx.bb0.l3:         andi x19, x19, 0x3f8                      
                    la x21, data2                             
                    add x19, x19, x21                         
                    fld f3, 0(x19)                            
pfx.bb0.l4:         andi x18, x18, 0x3f8                      
                    la x19, data1                             
                    add x18, x18, x19                         
                    fld f4, 0(x18)                            
pfx.bb0.l5:         andi x22, x22, 0x3f8                      
                    la x21, data3                             
                    add x22, x22, x21                         
                    fld f5, 8(x22)                            
pfx.bb0.l6:         andi x19, x19, 0x3f8                      
                    la x20, data5                             
                    add x19, x19, x20                         
                    fld f6, 24(x19)                           
pfx.bb0.l7:         andi x18, x18, 0x3f8                      
                    la x22, data7                             
                    add x18, x18, x22                         
                    fld f7, 24(x18)                           
pfx.bb0.l8:         andi x20, x20, 0x3f8                      
                    la x18, data2                             
                    add x20, x20, x18                         
                    fld f8, 8(x20)                            
pfx.bb0.l9:         andi x18, x18, 0x3f8                      
                    la x21, data5                             
                    add x18, x18, x21                         
                    fld f9, 24(x18)                           
pfx.bb0.l10:        addi x18, zero, 846                       
pfx.bb0.l11:        addi x19, zero, 308                       
pfx.bb0.l12:        addi x20, zero, 1325                      
pfx.bb0.l13:        addi x21, zero, 1645                      
pfx.bb0.l14:        addi x22, zero, 905                       
pfx.bb0.l15:        addi x23, zero, 1167                      
pfx.bb0.l16:        addi x24, zero, 2                         
pfx.bb0.l17:        addi x25, zero, 1418                      
pfx.bb0.l18:        addi x26, zero, 1915                      
pfx.bb0.l19:        addi x27, zero, 446                       
pfx.bb1:
pfx.bb1.l0:         addi a0, zero, 1452                       
pfx.bb1.l1:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l2:         addi a0, zero, 692                        
pfx.bb1.l3:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 24(a0)                             
pfx.bb1.l4:         addi a0, zero, 1586                       
pfx.bb1.l5:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l6:         addi a0, zero, 2023                       
pfx.bb1.l7:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l8:         addi a0, zero, 1449                       
pfx.bb1.l9:         andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l10:        addi a0, zero, 1029                       
pfx.bb1.l11:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 24(a0)                             
pfx.bb1.l12:        addi a0, zero, 2014                       
pfx.bb1.l13:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 0(a0)                              
pfx.bb1.l14:        addi a0, zero, 642                        
pfx.bb1.l15:        andi a0, a0, 0x3f8                        
                    la a1, secret                             
                    add a0, a0, a1                            
                    ld a1, 8(a0)                              
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
prp0.entry.l0:      fmin.d f4, f2, f1                         
prp0.entry.l1:      fclass.d x22, f1                          
prp0.entry.l2:      fence.i                                   
prp0.entry.l3:      slli x18, x19, 42                         
prp0.entry.l4:      fcvt.s.w f2, x22                          
prp0.entry.l5:      call fn4                                  
prp0.entry.l6:      xori x19, x20, 486                        
prp0.entry.l7:      blt x22, x19, prp0.bb0                    
prp0.bb0:
prp0.bb0.l0:        fcvt.w.d x18, f3                          
prp0.bb0.l1:        flt.s x22, f0, f2                         
prp0.bb0.l2:        bltu x19, x18, prp0.bb1                   
prp0.bb0.l3:        fcvt.lu.d x19, f2                         
prp0.bb0.l4:        mulw x18, x21, x19                        
prp0.bb0.l5:        la x18, prp0.bb1                          
                    jalr x20, 0(x18)                          
prp0.bb1:
prp0.bb1.l0:        fmv.w.x f4, x19                           
prp0.bb1.l1:        call fn0                                  
prp0.bb1.l2:        fsub.d f0, f2, f4, rtz                    
prp0.bb1.l3:        sltu x20, x21, x18                        
prp0.bb1.l4:        addi x18, x21, 61                         
prp0.bb1.l5:        fadd.s f3, f0, f2, rmm                    
prp0.bb1.l6:        beq x19, x21, prp0.exit                   
prp0.bb2:
prp0.bb2.l0:        mulw x18, x21, x19                        
prp0.bb2.l1:        fcvt.s.wu f3, x22                         
prp0.bb2.l2:        fcvt.s.lu f4, x22                         
prp0.bb2.l3:        flt.s x22, f2, f3                         
prp0.bb2.l4:        fsub.d f2, f1, f4, dyn                    
prp0.bb2.l5:        bne x19, x22, prp0.exit                   
prp0.bb2.l6:        bltu x19, x20, prp0.exit                  
prp0.bb3:
prp0.bb3.l0:        call fn1                                  
prp0.bb3.l1:        mulhu x21, x20, x18                       
prp0.bb3.l2:        call fn0                                  
prp0.bb3.l3:        fle.d x18, f2, f1                         
prp0.bb3.l4:        slt x20, x19, x22                         
prp0.bb3.l5:        fcvt.s.w f0, x22                          
prp0.bb3.l6:        bne x20, x19, prp0.exit                   
prp0.bb4:
prp0.bb4.l0:        call fn1                                  
prp0.bb4.l1:        fmin.s f4, f2, f1                         
prp0.bb4.l2:        fmadd.d f3, f4, f1, f0, rtz               
prp0.bb4.l3:        srl x22, x18, x21                         
prp0.bb4.l4:        fcvt.w.d x20, f3                          
prp0.bb4.l5:        fmv.x.d x21, f0                           
prp0.bb4.l6:        fclass.s x19, f1                          
prp0.bb4.l7:        sll x21, x20, x18                         
prp0.bb4.l8:        mulhu x18, x19, x21                       
prp0.bb4.l9:        bgeu x20, x18, prp0.exit                  
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      call fn4                                  
prp1.entry.l1:      fdiv.s f0, f4, f1, rdn                    
prp1.entry.l2:      fmsub.d f0, f4, f2, f3, rdn               
prp1.entry.l3:      fsqrt.s f4, f0, rmm                       
prp1.entry.l4:      fdiv.s f4, f3, f1, rtz                    
prp1.entry.l5:      blt x22, x19, prp1.bb1                    
prp1.bb0:
prp1.bb0.l0:        fcvt.l.s x19, f3                          
prp1.bb0.l1:        andi x18, x21, 1407                       
prp1.bb0.l2:        fmv.x.w x19, f2                           
prp1.bb0.l3:        fmul.s f4, f3, f0, dyn                    
prp1.bb0.l4:        fcvt.wu.d x20, f4                         
prp1.bb0.l5:        fcvt.d.lu f3, x21                         
prp1.bb0.l6:        fcvt.d.wu f0, x20                         
prp1.bb0.l7:        fcvt.s.lu f0, x22                         
prp1.bb0.l8:        bge x21, x18, prp1.bb1                    
prp1.bb1:
prp1.bb1.l0:        fmv.x.d x18, f1                           
prp1.bb1.l1:        fsub.d f1, f3, f4, dyn                    
prp1.bb1.l2:        srl x18, x20, x22                         
prp1.bb1.l3:        fclass.d x20, f3                          
prp1.bb1.l4:        call fn3                                  
prp1.bb1.l5:        call fn0                                  
prp1.bb1.l6:        jal x19, prp1.bb2                         
prp1.bb2:
prp1.bb2.l0:        feq.s x20, f2, f3                         
prp1.bb2.l1:        fmv.w.x f2, x20                           
prp1.bb2.l2:        fcvt.l.d x19, f4                          
prp1.bb2.l3:        mulhsu x20, x18, x22                      
prp1.bb2.l4:        fcvt.s.d f4, f4                           
prp1.bb2.l5:        fcvt.s.w f2, x20                          
prp1.bb2.l6:        fmax.d f2, f0, f3                         
prp1.bb2.l7:        fsgnjn.d f1, f4, f2                       
prp1.bb2.l8:        beq x19, x18, prp1.exit                   
prp1.bb3:
prp1.bb3.l0:        mul x18, x21, x20                         
prp1.bb3.l1:        fdiv.d f3, f0, f1, rne                    
prp1.bb3.l2:        fdiv.d f1, f0, f2, rne                    
prp1.bb3.l3:        mulw x22, x18, x19                        
prp1.bb3.l4:        srli x19, x21, 46                         
prp1.bb3.l5:        sra x22, x21, x18                         
prp1.bb3.l6:        beq x18, x21, prp1.exit                   
prp1.bb3.l7:        ori x19, x18, 1768                        
prp1.bb3.l8:        slli x19, x20, 61                         
prp1.bb3.l9:        bne x21, x22, prp1.bb4                    
prp1.bb4:
prp1.bb4.l0:        fsgnjx.d f3, f1, f0                       
prp1.bb4.l1:        fcvt.s.lu f1, x18                         
prp1.bb4.l2:        fcvt.d.l f0, x18                          
prp1.bb4.l3:        fadd.d f2, f4, f3, rne                    
prp1.bb4.l4:        bne x19, x21, prp1.exit                   
prp1.bb4.l5:        fcvt.s.l f2, x20                          
prp1.bb4.l6:        fcvt.d.wu f2, x18                         
prp1.bb4.l7:        fmadd.s f3, f1, f2, f0, dyn               
prp1.bb4.l8:        fcvt.s.w f4, x22                          
prp1.bb4.l9:        beq x18, x20, prp1.exit                   
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
tc.entry.l1:        call fn4                                  
tc.entry.l2:        remu x22, x21, x20                        
tc.entry.l3:        call fn1                                  
tc.entry.l4:        fsgnj.d f2, f4, f3                        
tc.entry.l5:        fmsub.d f4, f3, f0, f1, rmm               
tc.entry.l6:        fsgnjn.d f4, f0, f1                       
tc.entry.l7:        beq x22, x19, tc.bb1                      
tc.bb0:
                    spdoc_check_c
tc.bb0.l0:          divu x20, x19, x21                        
tc.bb0.l1:          remuw x22, x21, x19                       
tc.bb0.l2:          slt x19, x21, x20                         
tc.bb0.l3:          fsqrt.d f0, f4, rup                       
tc.bb0.l4:          fsqrt.d f2, f0, rmm                       
tc.bb0.l5:          andi x19, x19, 0x3f8                      
                    la x18, data2                             
                    add x19, x19, x18                         
                    amomax.d x22, x20, (x19)                  
tc.bb0.l6:          flt.s x19, f1, f0                         
tc.bb0.l7:          fsqrt.s f4, f1, rdn                       
tc.bb0.l8:          call fn0                                  
tc.bb0.l9:          fmsub.d f1, f2, f0, f3, rmm               
tc.bb0.l10:         bne x21, x20, tc.bb3                      
tc.bb1:
transient:
tsx:
tsx.entry:
tsx.entry.l0:       fsub.s f9, f6, f8, rup                    
tsx.entry.l1:       fadd.d f9, f5, f7, rdn                    
tsx.entry.l2:       andi x27, x27, 0x3f8                      
                    la x24, secret                            
                    add x27, x27, x24                         
                    flw f6, 8(x27)                            
tsx.entry.l3:       call fn2                                  
tsx.entry.l4:       fadd.d f8, f5, f6, rtz                    
tsx.entry.l5:       bne x27, x26, tsx.bb2                     
tsx.entry.l6:       bgeu x27, x25, tsx.bb2                    
tsx.bb0:
tsx.bb0.l0:         bne x24, x25, tsx.bb4                     
tsx.bb0.l1:         remuw x26, x25, x27                       
tsx.bb0.l2:         sltu x25, x23, x26                        
tsx.bb0.l3:         fle.s x23, f7, f8                         
tsx.bb0.l4:         mul x23, x25, x24                         
tsx.bb0.l5:         andi x25, x25, 0x3f8                      
                    la x26, secret                            
                    add x25, x25, x26                         
                    lb x24, 18(x25)                           
tsx.bb0.l6:         fcvt.l.d x23, f8                          
tsx.bb0.l7:         fdiv.d f8, f5, f9, rmm                    
tsx.bb0.l8:         bge x24, x26, tsx.bb1                     
tsx.bb1:
tsx.bb1.l0:         slli x24, x27, 40                         
tsx.bb1.l1:         andi x25, x25, 0x3f8                      
                    la x27, data0                             
                    add x25, x25, x27                         
                    amomax.d x26, x23, (x25)                  
tsx.bb1.l2:         lui x26, 3144                             
tsx.bb1.l3:         call fn3                                  
tsx.bb1.l4:         sltu x25, x26, x23                        
tsx.bb1.l5:         fence.i                                   
tsx.bb1.l6:         bge x27, x24, tsx.bb3                     
tsx.bb2:
tsx.bb2.l0:         andi x26, x26, 0x3f8                      
                    la x24, secret                            
                    add x26, x26, x24                         
                    sc.d x25, x23, (x26)                      
tsx.bb2.l1:         beq x26, x25, tsx.bb3                     
tsx.bb2.l2:         call fn2                                  
tsx.bb2.l3:         divu x23, x24, x26                        
tsx.bb2.l4:         andi x25, x25, 0x3f8                      
                    la x27, data0                             
                    add x25, x25, x27                         
                    amomax.w x26, x23, (x25)                  
tsx.bb2.l5:         fcvt.l.s x23, f5                          
tsx.bb2.l6:         fsub.s f5, f6, f7, rmm                    
tsx.bb2.l7:         call fn3                                  
tsx.bb2.l8:         la x23, tsx.exit                          
                    jalr x27, 0(x23)                          
tsx.bb2.l9:         call fn3                                  
tsx.bb2.l10:        bne x23, x27, tsx.bb3                     
tsx.bb3:
tsx.bb3.l0:         lui x26, 430                              
tsx.bb3.l1:         andi x24, x24, 0x3f8                      
                    la x25, data1                             
                    add x24, x24, x25                         
                    sb x27, 29(x24)                           
tsx.bb3.l2:         fsub.d f8, f7, f6, rmm                    
tsx.bb3.l3:         bne x26, x24, tsx.bb4                     
tsx.bb3.l4:         andi x23, x23, 0x3f8                      
                    la x25, data6                             
                    add x23, x23, x25                         
                    lhu x24, 22(x23)                          
tsx.bb3.l5:         fcvt.d.lu f7, x26                         
tsx.bb3.l6:         blt x23, x25, tsx.exit                    
tsx.bb4:
tsx.bb4.l0:         slti x24, x25, 154                        
tsx.bb4.l1:         xori x23, x27, 564                        
tsx.bb4.l2:         call fn4                                  
tsx.bb4.l3:         slliw x24, x23, 23                        
tsx.bb4.l4:         fmax.d f7, f9, f5                         
tsx.bb4.l5:         fmv.x.w x26, f8                           
tsx.bb4.l6:         fcvt.wu.d x23, f9                         
tsx.bb4.l7:         flt.d x23, f5, f7                         
tsx.bb4.l8:         fmul.s f8, f9, f6, rne                    
tsx.bb4.l9:         andi x25, x25, 0x3f8                      
                    la x26, data1                             
                    add x25, x25, x26                         
                    flw f9, 24(x25)                           
tsx.bb4.l10:        beq x23, x27, tsx.exit                    
tsx.exit:
transient_end:
tc.bb1.l0:          andi x21, x19, 1779                       
tc.bb1.l1:          mulw x20, x18, x22                        
tc.bb1.l2:          mulhu x21, x22, x18                       
tc.bb1.l3:          lui x19, 388                              
tc.bb1.l4:          andi x18, x18, 0x3f8                      
                    la x19, data3                             
                    add x18, x18, x19                         
                    amomin.d x22, x21, (x18)                  
tc.bb1.l5:          call fn0                                  
tc.bb1.l6:          call fn3                                  
tc.bb1.l7:          fcvt.w.d x20, f2                          
tc.bb1.l8:          blt x19, x20, tc.bb3                      
tc.bb1.l9:          bne x21, x20, tc.bb2                      
tc.bb2:
tc.bb2.l0:          mul x21, x18, x19                         
tc.bb2.l1:          fsgnjn.s f4, f1, f3                       
tc.bb2.l2:          fadd.d f4, f3, f1, dyn                    
tc.bb2.l3:          srli x20, x18, 48                         
tc.bb2.l4:          andi x19, x19, 0x3f8                      
                    la x20, data2                             
                    add x19, x19, x20                         
                    sh x21, 30(x19)                           
tc.bb2.l5:          andi x20, x20, 0x3f8                      
                    la x19, data1                             
                    add x20, x20, x19                         
                    amomin.w x22, x18, (x20)                  
tc.bb2.l6:          andi x22, x22, 0x3f8                      
                    la x21, data3                             
                    add x22, x22, x21                         
                    lb x18, 8(x22)                            
tc.bb2.l7:          bge x18, x22, tc.bb3                      
tc.bb3:
tc.bb3.l0:          fmsub.s f4, f0, f2, f3, rtz               
tc.bb3.l1:          andi x18, x18, 0x3f8                      
                    la x20, data1                             
                    add x18, x18, x20                         
                    flw f4, 24(x18)                           
tc.bb3.l2:          call fn2                                  
tc.bb3.l3:          srli x19, x21, 55                         
tc.bb3.l4:          andi x21, x21, 0x3f8                      
                    la x18, data6                             
                    add x21, x21, x18                         
                    amoadd.d x19, x20, (x21)                  
tc.bb3.l5:          fcvt.d.wu f2, x19                         
tc.bb3.l6:          fnmadd.s f0, f4, f1, f3, rtz              
tc.bb3.l7:          xor x22, x18, x20                         
tc.bb3.l8:          fadd.d f3, f4, f2, rne                    
tc.bb3.l9:          bne x18, x20, tc.exit                     
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
fn0.entry.l0:       xor x23, x26, x24                         
fn0.entry.l1:       fdiv.s f7, f5, f6, rne                    
fn0.entry.l2:       slti x27, x26, 285                        
fn0.entry.l3:       fmul.s f6, f7, f8, rdn                    
fn0.entry.l4:       fdiv.d f8, f5, f6, rtz                    
fn0.entry.l5:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       fmin.d f7, f8, f6                         
fn1.entry.l1:       fcvt.s.wu f6, x25                         
fn1.entry.l2:       sltu x25, x26, x24                        
fn1.entry.l3:       fadd.d f9, f7, f8, rne                    
fn1.entry.l4:       fle.s x26, f6, f8                         
fn1.entry.l5:       fmv.w.x f7, x26                           
fn1.entry.l6:       mul x23, x24, x25                         
fn1.entry.l7:       addiw x27, x25, 373                       
fn1.entry.l8:       fdiv.d f9, f8, f6, rmm                    
fn1.entry.l9:       fcvt.lu.s x27, f6                         
fn1.entry.l10:      ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       divuw x26, x24, x23                       
fn2.entry.l1:       slti x26, x24, 994                        
fn2.entry.l2:       fence.i                                   
fn2.entry.l3:       fnmadd.d f7, f6, f8, f9, rdn              
fn2.entry.l4:       mulhu x23, x26, x24                       
fn2.entry.l5:       fsub.s f5, f8, f7, rmm                    
fn2.entry.l6:       ret                                       
fn2.exit:
fn3:
.align 8
fn3.entry:
fn3.entry.l0:       remuw x25, x24, x26                       
fn3.entry.l1:       fadd.d f5, f6, f8, rdn                    
fn3.entry.l2:       remw x25, x24, x23                        
fn3.entry.l3:       mulh x27, x25, x23                        
fn3.entry.l4:       fmv.x.d x26, f8                           
fn3.entry.l5:       ori x23, x26, 97                          
fn3.entry.l6:       fsgnjx.d f7, f8, f5                       
fn3.entry.l7:       fclass.d x25, f7                          
fn3.entry.l8:       slliw x26, x25, 0                         
fn3.entry.l9:       ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       sra x24, x27, x26                         
fn4.entry.l1:       addiw x25, x27, 743                       
fn4.entry.l2:       fmax.s f9, f5, f6                         
fn4.entry.l3:       fclass.s x26, f5                          
fn4.entry.l4:       fsqrt.d f5, f7, rmm                       
fn4.entry.l5:       remuw x23, x26, x27                       
fn4.entry.l6:       sraiw x27, x25, 21                        
fn4.entry.l7:       fsgnjx.d f8, f6, f9                       
fn4.entry.l8:       xor x25, x23, x27                         
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
    .dword 0xaf2931357b40370c, 0x3d54ffeb07c51d28
    .dword 0x96298b966b1b8cd2, 0xccae875e6cdd32e9
    .dword 0xf88d783166c9c1dc, 0x92dcc3549874931c
    .dword 0xb30ed0df6b2a558d, 0xfdcd44aa117b906a
    .dword 0x7ebab1617ef0fb3e, 0xc01a1b9667bccde6
    .dword 0xfff6407bab788f7, 0x1a40dd782f64c42e
    .dword 0x3b9efc49172f6fcb, 0xc2588a5f4daf3fc9
    .dword 0xb65ced941656e58f, 0xd2cbe142e11f6497
    .dword 0x35f74b628847a904, 0xba9aeb9cafdc9605
    .dword 0x1a8497e1082ae40, 0x287eaa1ae84f7933
    .dword 0xb88841b88712683e, 0xffca0f5c1a6bedbc
    .dword 0x2c1a3cb77aea497e, 0xee0bb8f58ee5a385
    .dword 0x6fd4c2ed9544a64, 0x4f08e40e27ce40b9
    .dword 0xef7ddeaf146f1e0d, 0xbe0b8f6c0ee2b2d3
    .dword 0xe09a80ae84aed38e, 0x9d9ecd28bd52919d
    .dword 0xd1f854a2296cf352, 0x8d7416de724686c9
    .dword 0xa894179b60d51ed3, 0xe452ccd55768c4b8
    .dword 0x8e78fb88d2de621c, 0xebb1563741863744
    .dword 0xd0114882e42f4cb6, 0xa92866d27f013b8
    .dword 0xda79abe4b1aea114, 0xefc580b0cde3ae8
    .dword 0x667ed475f76ac29b, 0x21bb78ef032e3a15
    .dword 0xe2b628695e073183, 0x599b8238b925e0cb
    .dword 0x907b5b7ee9d9a19f, 0xb975719c78ce2979
    .dword 0x37dcbc13e3e99e84, 0x67f215e52148bd96
    .dword 0x8b0146aba417fc3, 0x4f8059a8fe9d2f2
    .dword 0xb3b50cbf44b692af, 0x9d5f695aa30ce198
    .dword 0xb5960d21439188a7, 0x8cbeb84ed6835fc3
    .dword 0x60bac845c6817805, 0x54a9a3dcf3017fb0
    .dword 0x62b1a91762628e47, 0x46b1fdb9ed1bc255
    .dword 0x7078b4b3bbee8a28, 0x694ed44d7f518ace
    .dword 0xe4b53ab8d8fba3fe, 0x99117858cadf104
    .dword 0x23dffc6bbe0d4229, 0x38cfcd53d943da78
    .dword 0xccac328d1fc21338, 0x21d8fcfda26bb617
    .dword 0xf4d94c6fbf2441c5, 0x6bc9c75142433fcf
    .dword 0x61e0a63134e16531, 0x6ec75dfcad646853
    .dword 0xdd0e093f642b5a5b, 0x571d1a75b4e55618
    .dword 0x6d1b7eb279c9e295, 0x53e2e496d7324267
    .dword 0x9f6695957800cfbe, 0xbd843e12e9658624
    .dword 0xc66ade5be10e2125, 0xdf514b1182f58007
    .dword 0x42744db153d0e3f2, 0x7dd450a8d1aaae7c
    .dword 0xcc636dbbfaa848f5, 0xc237ffb3a1c56b02
    .dword 0xc3e45ea6f093e786, 0x503dfebfe5461b9
    .dword 0xd65f52d546acfcf7, 0x2953b1b0510b5725
    .dword 0xee350c73217d2f06, 0xae566b67fd58a5e5
    .dword 0xc61cd52cb708925d, 0xf757461c0dfd63ae
    .dword 0xddb59951e583d428, 0x3ca2e4ef54db1f19
    .dword 0x4ecfaf9091c0e8f0, 0x61b7b63bdf81f127
    .dword 0x97925f9b77da487a, 0xc997acf0edcdec60
    .dword 0x9fd83d8f3d4e1f10, 0x354b6a4d194e37e4
    .dword 0xaa8b7adad83baa12, 0xd90df6028946525b
    .dword 0xfae8f99e934ac7e9, 0x50db8a4c989435f
    .dword 0x71f8417f77989fac, 0xcd3a0c7159e3085
    .dword 0x3648259c3554fb46, 0x272cef16ef3cc617
    .dword 0x50ad24dbee03ba29, 0x88dddfbf25c9e1ed
    .dword 0x7e9a755361b5fced, 0x4464d7794b1d4782
    .dword 0x90ebb7bc08d72f06, 0xda0666d9c54936fc
    .dword 0xf239e212adaaff, 0x4ab0a3332f704394
    .dword 0xb0dfac5ece4121d5, 0xb67a8be7c4dd9263
    .dword 0x2093107ff77974b3, 0x88ec4eb1e6d37aa7
    .dword 0xefbdaa108241cc4a, 0x4ecbad636b24efe4
    .dword 0xa6b4713162b85717, 0xcc7effb5257ef8aa
    .dword 0xe450d67d87152258, 0xbff1469b83a49289
    .dword 0x259e8e8be91b6bae, 0xb80aeaf1019b0886
    .dword 0x62a28123184c8f0f, 0xe966a699aa7b3247

    .align 12
data1:
    .dword 0xa0c2a494e1105ada, 0xc024905c4b8c6d2d
    .dword 0x27286210afb86a24, 0xbf372a5629aadefa
    .dword 0x80d1821d18ceb3e2, 0x22004e9a1ec529ef
    .dword 0xa5c29b9ec8ddb7a0, 0x6d229cc711977092
    .dword 0xb0d5ff5cea81408a, 0x25d5066c7676697d
    .dword 0x27a6ab91394c93ed, 0xf37db3f76ae79c67
    .dword 0xc7b4c4de07c0cfed, 0xda4c7cdfff4c4be5
    .dword 0x9aa5b226f449868a, 0x4df334c74735f5a6
    .dword 0x964b38893a99d524, 0xb34d8c10eeb20c7
    .dword 0x554399b54c73cb37, 0x5415b060355bc039
    .dword 0xc897d507942e103d, 0x4996df5e9865cb5e
    .dword 0x265145fafcb5efbf, 0x7d715e0a8074ffe7
    .dword 0x97af034752dd36c0, 0x75453c318c760eb6
    .dword 0xdacfff2488b51952, 0xc44d376aff1d283d
    .dword 0x28547b4dc097f627, 0x7112a1146045f457
    .dword 0x466042f92b7ad124, 0xdab4e6231e5f103
    .dword 0x84f1c3a111fc3b76, 0x3f23514cd360ece8
    .dword 0xbfd66c665a19e9f6, 0x4231f728c1e7675c
    .dword 0x1572e3e30dab1cea, 0xf15bac9015e45ae4
    .dword 0xac95e812b5244397, 0x19e3f678bd8a8a9b
    .dword 0x4ff710bcc7b31719, 0x2208fbfa7a2d21ec
    .dword 0xc5a8c2b69d296e3a, 0x63147b9248bf4e86
    .dword 0x8f86b408864f0e12, 0x607b69aab38e1813
    .dword 0xfcb40f6d5a5554ab, 0xe8ba5732b90e2c1a
    .dword 0x983fb1941c8b643a, 0xa83c3974627bc848
    .dword 0x7ca2ff425502f129, 0x9b5b0410d469a9e9
    .dword 0x7c1af5a369c79014, 0xaaf1bdc8666bc73
    .dword 0x91bcef9ebb5806, 0x4df0cb9be423127b
    .dword 0x58006daac4919a93, 0xf4179f6723bcbd
    .dword 0xaeec77b3f2393978, 0xbd16a0d3084f643e
    .dword 0x1f052c68b4a978fc, 0x96cd37ce52bac368
    .dword 0xf43712d7af435f27, 0xcab811d1d16f8c6b
    .dword 0xe66d97c71cac8146, 0x8151bdc36b4ae14e
    .dword 0x37895e5441bb8727, 0x5e15f1c89586644c
    .dword 0x54f96d95cdec517f, 0xdd81979eed3427b6
    .dword 0xe8967060fe7fd49e, 0xebb0130c76a804ce
    .dword 0x6b46f5cca7d221fc, 0x453dc25b4afb66c
    .dword 0x5dbab5968ea30b85, 0xa077689133a65e58
    .dword 0x328af6cef2e59366, 0xe6ca2f2f32646b16
    .dword 0xe8069e8b437e2fd, 0xa8d3f910008b7c0
    .dword 0xfabab6d06ee7806d, 0xc32cf330fb0f719c
    .dword 0xb899b21507a4fa8b, 0xc41f0fb93c63c72c
    .dword 0xe80ebc482da99ab, 0x6fa02f3a88811796
    .dword 0xab4e7be14daac7ba, 0x151410ac48bcda48
    .dword 0xe7f4d62af0d0bb7, 0x3170ffffad13388b
    .dword 0x3df92b7f6d38ceb0, 0x3c44b3aed162d46e
    .dword 0xab9059892e69c685, 0x92526d64763f1187
    .dword 0x932ccbfd7a4d569, 0x182cde7d931f06ac
    .dword 0xd7ec33a7ffa91bf1, 0xb74c644284a42dec
    .dword 0xfbded89488e72a97, 0x8c125c4c1cec6b71
    .dword 0x2b13b2be8c8aaed7, 0x770a9a4ed272fe1c
    .dword 0xdfc19dad4a0e9ad5, 0xb760412e15d0e17d
    .dword 0x182f2a9eadb38199, 0x22260de4ec3c1c83
    .dword 0x68e1be1f21f9e1e8, 0x9e2940706e7bfa0d
    .dword 0xa07288102e05dbaa, 0xb3a4fd11b38f9ad5
    .dword 0xd58e6c1dc9a1548f, 0x3d661a6a59c62926
    .dword 0xfa7c7815e0277835, 0x2cbd91c71f2f2cf0
    .dword 0xe4d607d288fa7147, 0x90ac27e61964a597
    .dword 0x1b58db610d250734, 0x3ac0b4af79d9c36c
    .dword 0xc0c19c618e282ea9, 0x3cddc710168c3492
    .dword 0xd1580a8f913a10ad, 0x410104219d4ddc9c
    .dword 0xec1e8a13d57fac36, 0xa69199d9c8a486cb
    .dword 0x38011330f645cc10, 0x5c3734d34f97cce2
    .dword 0x794ea067cec928f5, 0xa9f004f9f6e538e3

    .align 12
data2:
    .dword 0xd2f4dcd64c20bf84, 0xa4c0fbc6ba6e3bf6
    .dword 0x2a3109dec64e6b45, 0xcc07b68376503d8b
    .dword 0xc167021336abecc2, 0xe4cebe52534a5e0b
    .dword 0x9acc14c04116aa77, 0xf08c760b5524948c
    .dword 0x893bab68a079eef0, 0xe9e46f1c16baa28f
    .dword 0x90f0f9177787d909, 0x9ef2484d265f5e0b
    .dword 0x65fa6dd79ce5216f, 0xe9697317c14ef6c2
    .dword 0x3fc7013624ed7371, 0x8c4933b333e5d2f8
    .dword 0xab6a464104059d28, 0xf755c625d14043c1
    .dword 0x6b3704308770f414, 0xc72edd1bf0f9753c
    .dword 0xd14b9e619d3158ee, 0x19f1f32a7d9d6b83
    .dword 0xdf9ffaef8970c8df, 0xcf4c621a00b82874
    .dword 0xea7161a52b1944d0, 0x9244b471b117b890
    .dword 0xd5767ffaeb6b3339, 0x35ab7772873c3112
    .dword 0x39a03dc7a8c5fcd2, 0xb3785533e9550c7f
    .dword 0xfa55bedcf5ef6aea, 0xb5fc6f2a6e25f8e7
    .dword 0xc4264d99e1f36a05, 0xad7a3ebc2c3b522
    .dword 0xd711d4c3025be0a, 0xca06a57ea11a1e96
    .dword 0x76af0b7975d6ea19, 0xcda6c7a830ed267e
    .dword 0x38c1db32c70f5b87, 0x97d83edbdccbbcaf
    .dword 0x68cc4e4f2f8d1f9e, 0x62f9e87a2eeec116
    .dword 0x820eb4a0c90d8f77, 0xb3040ea376a5de5a
    .dword 0x4f5740c6602042e0, 0xc7873c39ed0e4741
    .dword 0xa67ab3f7b14c90b3, 0xf247fab71e776246
    .dword 0xbeb4a2cd457bc42, 0x66bb14afc2df9ee
    .dword 0x935887db0d97795d, 0xb78ce6368da92b0a
    .dword 0x2c73faba575e421f, 0x33e50670bacaf819
    .dword 0x49955eefd661b70b, 0xce8c68010104378
    .dword 0x408570628094adf, 0xf9ed725dc7147a9b
    .dword 0xeeea9a6476e29f89, 0x3c63285921a9351e
    .dword 0x5089bb9dd4c79913, 0xc43acbf51ce3cc7e
    .dword 0xdd5681f9aeea0079, 0xe641731e7a221086
    .dword 0x2745065658947bd5, 0xc51546e43427c38f
    .dword 0x6efa1f2ff357e5dd, 0xf05afb3031c9a255
    .dword 0xe57579388ae40cf3, 0xb35612fbbc90ae16
    .dword 0x5da35b3d9f9d2810, 0x882ce13d5d10132d
    .dword 0x1afdedb61f1a063b, 0x1d929184d3a21779
    .dword 0xc11c254203bfdcbc, 0x9bf563b90d3c38ae
    .dword 0x8eb501544167cdd6, 0xffa22d54e6721ea3
    .dword 0x536a932785e5f3eb, 0x78c5dcbb46cdbe1c
    .dword 0x72e4b73052e70507, 0x47ff307e56c4af4f
    .dword 0xa21c60bd4ad17302, 0xa69817f98ec6efdc
    .dword 0x5e2777aee1e2150d, 0xc696f72f886d444b
    .dword 0xc6517503471fbcc0, 0x533f210a54246211
    .dword 0xbd1c1b619178506c, 0x5f509e20da1460fc
    .dword 0xe57ba8c757fb20e9, 0x7b764231de049681
    .dword 0x2138900e4d790b0a, 0x5121063de50f6afe
    .dword 0xfa39462456310dc7, 0x3f4fbd3a9d68d734
    .dword 0xd445d1ed43f0b3bf, 0x863e15394661d4b0
    .dword 0xe6214179ba0b8a11, 0x489fb6c4c8989162
    .dword 0x56dd64f38c6f59cd, 0x19cedaea9f1ed6a7
    .dword 0xe5c002ed7d531c72, 0x66bd24180ca37991
    .dword 0xb979872be0d60579, 0x31fe2c313a961720
    .dword 0x600fb8f7a2142be0, 0x75b23817864be7d3
    .dword 0x8086220735350300, 0x858dd1ca7649f540
    .dword 0xc594c1e8c013437d, 0x92509213dea9942c
    .dword 0x905524c557eb5115, 0x3de44a1cc0a9aa34
    .dword 0x2cb4ba8d3d9ab440, 0xf34db268426ad757
    .dword 0x8c9ea3508fe876d2, 0x2f3dfc60945d4bdd
    .dword 0xb54881395d76cdf9, 0x3fb05753552854e5
    .dword 0x5e83abe9653e8837, 0x8ae93d0b6069608f
    .dword 0x7c14a2d322608024, 0x490c60d6c2a8217a
    .dword 0x64317aff6edcd6da, 0xb870de12214e89c4
    .dword 0x25d63cf4959e754e, 0x99c8d8ad8edf9

    .align 12
data3:
    .dword 0xd280749318a1498f, 0xd3a99ec1728f1c2
    .dword 0xe26352f2b16a3c7c, 0xfd9c7a3bc39c4255
    .dword 0x8b7ec32143580339, 0xe20f06d6f7bd12ab
    .dword 0x333279dab3843f70, 0xd3e0cf47d58727da
    .dword 0x7e724a8b5446440, 0xc529fce8d8e95501
    .dword 0xdce89461420c5445, 0xbfc532e19cf53389
    .dword 0xb3e54566822989b8, 0xf6c4b1c282af29a6
    .dword 0x67804106e98d6ee4, 0x8cb5060d8acca499
    .dword 0x6dc88fed6aa8785, 0x1988dde22fac663a
    .dword 0x829daae1b2f65057, 0xfd465303a2006c26
    .dword 0xe70ee40dc492a847, 0xa09b47d2713d467c
    .dword 0xe93a99079709e3f4, 0xc962cf7007e6b240
    .dword 0xa43c052003691204, 0x28598171e0e901d5
    .dword 0x69018fac0a970bc4, 0xf194d41cec2c5f80
    .dword 0xdd54a5e236211f21, 0x131cbc9cae1bef53
    .dword 0x813a04e5a7d8f0bb, 0xc21f5f8c5d062ad0
    .dword 0x4849574eb6ff5e69, 0x3d3b47e7e8acce7b
    .dword 0x689a67b734f70f4d, 0x1a62e18afc299cd9
    .dword 0x93306df7d7f5b05e, 0x3ddda4c615000f4a
    .dword 0xe180c335d5dca99f, 0xe71dfb2226fbfd76
    .dword 0xbd620fc6dae34bd5, 0x3eb01945073773b8
    .dword 0x1b4e5f4a4cbf6204, 0xfc89790db5bdc927
    .dword 0x929b9cb5635631a4, 0x838f65e54a7631e9
    .dword 0xac39319fab5ba999, 0x385082f0c777cb01
    .dword 0xf157577036e8061b, 0x97e1a7110c4ed8d1
    .dword 0x7609ac374b957cf, 0x781a975c8d50182
    .dword 0x603ae432c243e278, 0x46e8088ef5bf983d
    .dword 0x135f85d73eb4ebb8, 0x5e5731f365531fff
    .dword 0x92813f8e94d4933e, 0xab89497dba4e1099
    .dword 0x7772f3d2e73a7377, 0xd4fac5ff3e301e5c
    .dword 0xeb761b1c661173ae, 0xb8b118a48c16ceef
    .dword 0xf9192829f821a0eb, 0x5053c0bf53350e6a
    .dword 0x98a9172074a56358, 0x3e5abd59e075692c
    .dword 0xc2d2979e181eef15, 0xe9f0d2cfbef6a719
    .dword 0x7cac974888c3de84, 0x8e1ac54dad6777e6
    .dword 0x1ac92ec369c5dfa5, 0x78fd886e59bfa0a6
    .dword 0xc32650879223f17f, 0xee05e1110f4dc4ef
    .dword 0xd23ea37da160722a, 0xb3062a97a11cc84e
    .dword 0xfeca7e0eba172b05, 0x765f11309a261395
    .dword 0x39ccb072736cc21b, 0x7f5db490ed63d5df
    .dword 0x7d2aad6b81640d68, 0x125af8d2ce581994
    .dword 0x5f17ab7ab879aea7, 0x9b25ca4eb99a7e22
    .dword 0x53009d2e84f40443, 0xe17d7c8d6221867a
    .dword 0xc419474180c6ed82, 0x57375cd9aaca644b
    .dword 0xc689d706aeb79bc8, 0xebce0c0ffd25596b
    .dword 0xe93881c7014a7306, 0xb53a39e44520f02b
    .dword 0x6949f125e6f21993, 0xc66de5e01942e438
    .dword 0xea845a8751c9b3bc, 0xd2a6942fb3600f39
    .dword 0xa6b6abd7933dd862, 0x1af39497449084a
    .dword 0x98dff6168113808f, 0xe8b72a6f2e48a414
    .dword 0x6de02df5b6c3ddee, 0x11426582cbb70c68
    .dword 0xaa8facdb554acdbe, 0xa3b8d0189d43f2a7
    .dword 0x5a03539d88c47ca8, 0xc741e27b577b099
    .dword 0x925dfc352098ab4d, 0x2f8cc895bd861267
    .dword 0xb5b591b5280ab7e6, 0xd0843f8fade3c6ca
    .dword 0x81371c832dacda17, 0x15aebff3db67d327
    .dword 0x9eff78652951884f, 0x758acdd8794fbe4b
    .dword 0xd1c04f1902da4736, 0xc9e9d3541726e434
    .dword 0x2ce03b066bbecaef, 0x97aa6eb437470072
    .dword 0x2bd589fe5be81068, 0xb1239a37b9edc572
    .dword 0x2bf965a8de0cc083, 0x43ef8249a5ca4da3
    .dword 0x63a5f92910683de6, 0x18d1837a93bc3f9
    .dword 0x97e0475e1dd05d3c, 0xed6266e14304bf7a
    .dword 0x2cd036b6729439ad, 0xb87d3a7cdbd60887

    .align 12
data4:
    .dword 0x21bf8bd56b647db4, 0x8bf3d0105aa8a337
    .dword 0x440d5b7fadd750f2, 0x6f142ba37333fb82
    .dword 0xf9ffb5e8d55755e2, 0x71b621cc6fc881e8
    .dword 0x223b8a26deab1627, 0x29de868354bd6bb9
    .dword 0x445896cae5525dd5, 0x4c6812711a584ff6
    .dword 0x4536396e552a5c2c, 0xaeeb4701fa71cc40
    .dword 0x95b2fcbf56d7bd45, 0xcaf45f422b3ef5e6
    .dword 0x5f075d1e113f09c6, 0xae244c16b725cc01
    .dword 0xf3a3ad6a9400298, 0x88bb914cee761348
    .dword 0x50e14b645edddb36, 0x81c564a7e9603875
    .dword 0x270282723ebb33ee, 0xbd38d205716f2a89
    .dword 0xb48d9ebe9beeebf6, 0xcdc6fd928552fe7a
    .dword 0x97cb0664ec64cac, 0x37a0fecef5df9821
    .dword 0xc38fd6f98162f049, 0x5c1906578bb348f9
    .dword 0x622e7e5c37f2ce72, 0xf3cf175befd12811
    .dword 0xa0e2900efd7a50fe, 0xd48d4fd0578a48c1
    .dword 0xc935606bac71b4bf, 0xb5abdda4c25df5fa
    .dword 0x4ab7544c4314c33f, 0x280cf8c10fac5e19
    .dword 0xf6c65e63944122dd, 0xd2ec0c2f4cdcf767
    .dword 0x11f4946953754ab2, 0x6fe2e1a4ee5f30e5
    .dword 0x7a6e20199c25fbf, 0xcec3a85fd8786d2a
    .dword 0xd7369ec37ee5846c, 0x6260d49e7e650dfc
    .dword 0xd65869f133c4ced1, 0x1c57543ce843a2e4
    .dword 0xd7f5afec6b61c0eb, 0x7db52a32c5464ec9
    .dword 0x3dae288b556c52bd, 0xc27cd27c8e53bb07
    .dword 0xf9901c9366492653, 0x870ec994c75228c9
    .dword 0xab8c27aa8ef17589, 0xef80c50fcc23f3f0
    .dword 0x52d3a15bd8876588, 0xe376f9e636a14f8b
    .dword 0x513bbbe118925aa1, 0x597798e950c1b6f
    .dword 0x556109f0797fdc57, 0xabc9339db5a43ae6
    .dword 0x9af3db21b55ae97e, 0x9beba25139f19cb9
    .dword 0xd8190495da85253c, 0x8f0bd9f9b44408f7
    .dword 0xf4a87d6fd5ce25c1, 0x82fa97b097643aa2
    .dword 0x2571da0b8a0061e9, 0x1c4a040942deb239
    .dword 0x280404c57ae54246, 0xe1a9c46dc1bccf88
    .dword 0x995c87c0641f97a5, 0x44c7fe00a8b4a39d
    .dword 0xb8d4e03e4deb4a55, 0xb365c1b670cd8b03
    .dword 0xef14276f6ab8135b, 0x1521dc5ee0a29c6c
    .dword 0xa1bb1554b731a88d, 0x668d3ee2bf6c8a78
    .dword 0x872380cfd6043d02, 0x18c8060f43a228eb
    .dword 0xc0599b939bf623a3, 0xaaa553c9ac2dd122
    .dword 0x9671bd67ac8952eb, 0xa4dcdbd195a1c2b7
    .dword 0xc91deff967eb67d1, 0x62b942c5111ab60f
    .dword 0xedad7b8fd2dadd6, 0x93c4f7b16c7d7393
    .dword 0x52e10e1be5255082, 0xd277563cf8b4a395
    .dword 0x11fce761484c5f0e, 0x28fc46b0dbb21dd
    .dword 0xcf3b567b31e8293b, 0x32706c1fb457439d
    .dword 0x4a8229c24dbadbb3, 0x82f71216bffc2264
    .dword 0xcddd20e2e1a508c5, 0x985f3afb04c1750
    .dword 0xfa9bf50df6c89ada, 0xdc0e4217279e1bb7
    .dword 0x7aed2e1a44fc4a1, 0x31ae7a72ab2b32fe
    .dword 0x8b6ea23c79da3ee5, 0x4d355eef58cc9cf7
    .dword 0x25d4bd4f93b1b78d, 0x5206afc49f6d4bd2
    .dword 0xe5a7f25fe312a24b, 0xd04c2f9de9b6acb9
    .dword 0xf41a12133e1fe1df, 0x6b1aca586e9940d8
    .dword 0x91534a7899a62535, 0xb29c9277143dd364
    .dword 0xd7f62135f98f0ce9, 0x482894dc18229be
    .dword 0x9ded201df319c8f8, 0x3b0bf9f03091af76
    .dword 0x10622f8fc931701, 0x1e1e38f756a467b7
    .dword 0xa1c3e546dbec9b75, 0xae014564f2f5db8a
    .dword 0x997b3206c7c8e939, 0xacd0209b6a4104ac
    .dword 0xf4ddb085043eea9, 0xc92b17ff3bf8791e
    .dword 0x2525a258b29e1a6f, 0x87d8ee706d2c81b
    .dword 0xc341bff29392cd12, 0x10c8e43e9d6b12a0

    .align 12
data5:
    .dword 0x48474e4f8741c0e6, 0x64f84894e84016b5
    .dword 0x4cbffcf867e96ad7, 0x9d2ae2c6e118d71e
    .dword 0xd8f39dddfeb8bb4c, 0xf4a713e786ec5027
    .dword 0xbe0b41ceab9e3a2, 0xd701c8e895d82525
    .dword 0x4120b985126e102c, 0x99b1bbdec3f815c
    .dword 0xc9c8387fcdbada55, 0xdf88b8f0d8c4d4c3
    .dword 0xc9de760c728e3cc2, 0x2f9c89aed21bbc90
    .dword 0x4dbafa45f757c283, 0xa91f6289778d4292
    .dword 0xc77ce27e7705d7c3, 0x52057eb32a9c7716
    .dword 0x6f85509986ad77e6, 0xacc5fe099888d845
    .dword 0x5862a8f373232390, 0x72289352ee31a121
    .dword 0xec80d91719393209, 0x830f75010656a844
    .dword 0x2982ae5a5e775a2e, 0x75cc287cdb62eeb6
    .dword 0x10fe55d564d33c96, 0x10d9d0b3916a6655
    .dword 0xea48e6193c5026f3, 0x51aa7d7d1bcfa4f9
    .dword 0xd96e76eda3a32f61, 0xd907a332fa2fb10
    .dword 0xc311ce706c181f, 0xe205297922f9f680
    .dword 0xe27d9ea51d38c954, 0x772478b13f51cb41
    .dword 0x4c035d347416e455, 0x19b83f323928bb5c
    .dword 0x4caddf7101b4644e, 0xc43df258842c042f
    .dword 0x6d7f5d977e6c2e89, 0x5517d66c0b01fd3b
    .dword 0xb05a43a6f9c11e10, 0x1b76cff259104647
    .dword 0x8b04fb0439d8a0dd, 0xf1384e5459563603
    .dword 0x13f340b34dd398ab, 0x7136fefbdc5f9c9a
    .dword 0x1f871a817ee88807, 0xd6b6ed21c665c591
    .dword 0x32470475b7c1700e, 0x788a78703f3909c9
    .dword 0xc27f28f8d5b67a29, 0xf8a4d62dbfba05f3
    .dword 0xc827312771cced47, 0xbfa8c74cd314b495
    .dword 0x2920bc21b671e38d, 0xa995f29cc0a0a725
    .dword 0x38e72e4abe2934, 0xd77cadb100e585ce
    .dword 0x69891575e8f0d4a1, 0x564d59216f798a51
    .dword 0xd6b62ad01d12c5ed, 0xe13326e1fddde660
    .dword 0xaea5c041545090f0, 0x11c0b1f13cfecf52
    .dword 0x7c628228c081d261, 0x2d3677e0c1aa1140
    .dword 0xfe611e334b2972d9, 0x5daf8d27538492c3
    .dword 0x273f4da30afe6cc9, 0x8143a8ee5e06b8b7
    .dword 0x1ea35b800baa8cc4, 0x64882cb586133a0d
    .dword 0xb01f432e2e7c389f, 0x2f67987579fdd508
    .dword 0xc1b0a82cb954fdb0, 0x222d3c4128e46fc2
    .dword 0x157cccdc9cffe092, 0x849362d259305a6b
    .dword 0xaa093ae7e294ca5, 0xeb1d4e3cde7b358a
    .dword 0x746cd9506a43c07a, 0xece62cfac4e188d
    .dword 0xf200c49bd42a79b7, 0xd8d41f71103a89ed
    .dword 0xb60ed39c6a862769, 0xbc0bc067a0af7373
    .dword 0xbe2d734a2c968615, 0xbaa68941cf6662d3
    .dword 0x7e96a38bb278d29b, 0x5f94ebbc3d9259d4
    .dword 0xa648bec540c4a688, 0x93b94c458910ca1e
    .dword 0xdd1683bfd49ee5ae, 0xb5d705fe360da07d
    .dword 0xd2f34519c8aff1f, 0xbad198d8566f8a00
    .dword 0xccadb327396d97f5, 0xd16e641bd43e54fc
    .dword 0x331e09073af0a291, 0xff1a39366699c0a0
    .dword 0xd28386b6c757d88b, 0x67999900774a191a
    .dword 0xf2f8cf9e72880e9a, 0x420e0a30f75fda50
    .dword 0x3dba09c98f15b9e8, 0xc6c691dab4a8406
    .dword 0x3dd98392e10ff001, 0xc032958a4c21f72d
    .dword 0xc3118e4785df07cc, 0x11c170f278042b45
    .dword 0x62f7e752063d2fd4, 0x25dc867266f90d6
    .dword 0x80798ffc039e14e8, 0x497e5fc66ff00018
    .dword 0x8e44e6788bc3cacc, 0x1d7a21529c372dcb
    .dword 0x85e2b61d1a41732c, 0x3a3f87900949ccff
    .dword 0x34ae65178fadef3d, 0x575646b0d726395a
    .dword 0x691be1136a2c2f37, 0x9ea4f7cbe25b8fa6
    .dword 0xe573900b02506174, 0xd69f06f22bbcacb
    .dword 0x8252c6a68040a27f, 0xeb8cd6ee469ce361

    .align 12
data6:
    .dword 0x64e67e81459a7134, 0xbd183cb8666bd537
    .dword 0x22320f852fda6b57, 0xe9e71b9ee01944
    .dword 0x7fc09be7bc7a2694, 0x25d17b16bead0ebf
    .dword 0x94ec4bf4fb8cb6cb, 0xc005a9a87547a180
    .dword 0xe914bc2e4275d159, 0x1e007d45f0c6607
    .dword 0xf7c33992bb699e81, 0x4158137356c1d71d
    .dword 0x708fee05e8b4d461, 0xa268c74859763699
    .dword 0xa5267edf06b74241, 0x8d57db4672ba6e5f
    .dword 0x8dad027b0f37d704, 0xf23b71d2690f77c
    .dword 0xd73db37f96eed78a, 0xeeefcb5adfc1d18
    .dword 0xbb30eb33f5b6e55b, 0xe475410b2bf9dfcf
    .dword 0xa4ac955a382965de, 0xc16a6ee47c25eecd
    .dword 0x80b5010d7a836309, 0xa626c3952ba461bd
    .dword 0x499376284ac7f322, 0x70eb829b0723a837
    .dword 0x1f7f4d4e93ff7bdf, 0x57088ae230e39fd4
    .dword 0x9d5b2a24466679c8, 0xf8bf107267cef507
    .dword 0x166c3afb43478af0, 0x94ca78cc87a8508a
    .dword 0xfec0a5957dc43704, 0x8b7264912cf7312c
    .dword 0x932ca42c1f94bc49, 0xbeb68b18c168be8b
    .dword 0xafec8490ee7529fc, 0xe3d4dacb5db067cf
    .dword 0x325750c8e7ad8aed, 0x4d2be0e1277f8077
    .dword 0x2c143668c6836b0d, 0xf176a3652f1d1aa4
    .dword 0x5af424c5692dba8c, 0xd473724a8e25ace1
    .dword 0x5341c0313012ad15, 0x235bcefa1a02c26f
    .dword 0x8dfc026c16ad5904, 0x51dcb99358235dd7
    .dword 0x1957135db6ff041f, 0xb8f17e77ae041ab7
    .dword 0x59ea3b0272a6ec37, 0xda8ad0f5dee7bf68
    .dword 0x35199fcc6136f322, 0x6c5f790121431c52
    .dword 0x605c0fcfc87583aa, 0xef87e11a9184cb09
    .dword 0x8e6eaf421b9db518, 0xa88b2680a4df7834
    .dword 0xe954850865ec4e6d, 0x501f6fe007ea44d8
    .dword 0x3d95d992dbc6dbe5, 0xb0a89a3101c7d8d1
    .dword 0x9e498fb61c0a331, 0x3a068aa7f973abf
    .dword 0xa5dffe906edec7ab, 0x78b1778993b4a423
    .dword 0x65e7ec8fb21bd2e0, 0xa91a3aa3d8f94aa4
    .dword 0xbd99247e94eb70e9, 0xaf5b1ff91d973eed
    .dword 0x540f8120b2302e02, 0x669188041720ad64
    .dword 0x80a798d3d25e6b0c, 0x493bb088798c9da8
    .dword 0x654a6740fc6369d6, 0x95d5a7e6186e898b
    .dword 0xe0024dcfe47130f2, 0x6149dc253a475e93
    .dword 0x9afee83fc75e7b9b, 0x5a9421649aa91e1a
    .dword 0x6a1377f41e88b241, 0x313539fa0ec7d158
    .dword 0xef04e8a3552d81f3, 0x56db0a18172804eb
    .dword 0x6e19d69ddfb177c8, 0x6913f5a663d90546
    .dword 0xcfb6992bf85dde, 0x1560615a2054320d
    .dword 0x5e13ba963f54b063, 0x602fc3bb3ac4bd5f
    .dword 0x138988f4c95a835d, 0x3dd1ea20730cb5ba
    .dword 0x7eb339c6ae7d197b, 0xb0728e5918ca58ae
    .dword 0xb4fbf564aed75ee8, 0xb0fb35707d7f64dc
    .dword 0xa57284919c91c37d, 0x71e3a6fdb0552267
    .dword 0xa7cf1f58caf5da51, 0xb97f4ce6c6353adb
    .dword 0x45e47e460b71c0e5, 0x425cfca330e2ceaa
    .dword 0x275d2c8a10875d36, 0x50916788b5367938
    .dword 0xec8780fa55be6a8f, 0x3862c13c4677cfe1
    .dword 0x67811faeb25e3e1f, 0xca20aae54be72ef
    .dword 0x124a358fe25fbbb, 0xd5d239b1010894c8
    .dword 0x59d37ee946fc9f3e, 0x7b103376384ab3a8
    .dword 0xc85b5a5b856684a, 0x1e2233daaa4d6463
    .dword 0x20949b8bd895a90, 0xc009c9f6abf02e22
    .dword 0x4664c5b45ac17640, 0x18f51e3cd3b521e7
    .dword 0x1fa339515532f20, 0x4b7539e245cfc1f7
    .dword 0xbbe847310b1cfc21, 0x398798d9ddd6e7a8
    .dword 0xd67d1f3a3a1b8beb, 0x294093f9186689a5
    .dword 0xbdd4fbbd7caa0792, 0x73e0e4d2ad027c4b

    .align 12
data7:
    .dword 0x6f3baf2020945e1b, 0x7dce562b19a88b4b
    .dword 0x4dc9d3fe4243600c, 0x5c3e798781982205
    .dword 0x545c12974122d560, 0xd56deb07684c9e94
    .dword 0xe067ffa797833647, 0x5de15a693ddba795
    .dword 0xe5090822ee1def4f, 0x598da05d9ffa37c
    .dword 0x387e3106074c0ccb, 0x32e0e580c0d3cd84
    .dword 0x2487a704aa18bece, 0x791bb3ab304fa31d
    .dword 0x8bf4ea7fb5d6b978, 0xde9dff861aa5a863
    .dword 0xa05a2767c192665b, 0xb971fd249a6ca5be
    .dword 0xef304ebc0943dba3, 0xbbbe1a4ef0f9d13b
    .dword 0x14eca0bf38473702, 0xdc56aa28b17c6a34
    .dword 0xe0f9711ef2f15289, 0x4168506e579eaf4c
    .dword 0x43c4faababb1b8ca, 0xd701a9b404597ff8
    .dword 0xee82793a5b7418ad, 0x69a0a6605d1a6c94
    .dword 0x496f88c7ba1353e4, 0x7b0e4d88427f2679
    .dword 0x7a66bcf88e18697b, 0xc57f1ada816090da
    .dword 0x2bf4beb3c34ae7f4, 0x499660de865d1a98
    .dword 0x5a243f2d203b3338, 0x9f56da3838303665
    .dword 0x6b750699b4e8d613, 0xe08877410446f62a
    .dword 0x502b23a63b5ade7b, 0x17869ac8f00f2de2
    .dword 0x702f55b2a9a2ffe5, 0x1dca351437268bc4
    .dword 0x1ed7a6856e6735bb, 0x72a15c693da02033
    .dword 0xa793683b3ac53264, 0x7802a766b9506d3
    .dword 0xec2250b5f2d7626, 0x191a1a2238948890
    .dword 0xbc529a1093be9a0a, 0xfb62a963aae3ec72
    .dword 0x9cc531526fb91890, 0x6c57a023c3b83c6d
    .dword 0xd1ba8e6c4fcb6b78, 0x50db2573e6bdfa3d
    .dword 0x2c787375b260e9ce, 0xaf87f3a03063281
    .dword 0x8b96c335134f539d, 0xeda362d5c696c925
    .dword 0xed55499a3ec6c496, 0xda7b7a8af9a53ca6
    .dword 0x19928ccec820dd56, 0xa4afc9a89f7699a
    .dword 0x504b10873a9afa25, 0x11209cca2d64f112
    .dword 0x5ee62d61fd6a65d, 0xd3a1d368310297b
    .dword 0xca2bb5378cfca36c, 0x3f2192f66938ef4
    .dword 0x705f90b22a2bd0e9, 0x44a2230ddb36046e
    .dword 0x6348cd1443b0f3d0, 0x43fb7e9653ed0620
    .dword 0xb366b3224d5f5609, 0xb678bfa7fafc8d0
    .dword 0x551dca2fc7a40397, 0xd8aedabebc666455
    .dword 0xfb29caa32af129b3, 0x2ae0492e6c0db00c
    .dword 0x85187be5085952a7, 0x480e6f903eee31fc
    .dword 0x97a2252321cfde4c, 0xa7f7fb680ec73e85
    .dword 0x59bdd5abb94c307, 0x10a9c0352e4f36b4
    .dword 0xb73207de853606d0, 0x9b1bb3f7def05cb4
    .dword 0x6e616e53edb36509, 0x126b646a458824e6
    .dword 0xed92ddb4a1c884c4, 0xa8eba313daecea92
    .dword 0x8e0287d688670486, 0x10cd16b02cffb064
    .dword 0x3540598f684d07c4, 0x6fbe0c8aa04954b7
    .dword 0xe6b23d46037587b1, 0x4eda7f3548e45f8c
    .dword 0x163824bcc9b35836, 0xef82e2e8c01cabbc
    .dword 0x58d978399df75126, 0x1f121cb6e509eee7
    .dword 0x93a4ea32a810d43b, 0xa75caa9a0e5e4480
    .dword 0x4b6537444e558bc5, 0x1dc9d20b15710293
    .dword 0x2258c928bfaf10a5, 0x84d0c082dedcd831
    .dword 0x3595df6f4c38094b, 0x61f93f10a90701db
    .dword 0xaae318304aada64c, 0xbebcbc1e47affeb
    .dword 0x4b1a7290c1584d38, 0x4b5156d455d76a8b
    .dword 0x3fb2f1b76f68b4a5, 0x7a8b746eb5e427c0
    .dword 0x4af17fee6fef9c8a, 0x3abb2f6ad8493861
    .dword 0xb3ae823cf533df6a, 0x5e8be6eac3567265
    .dword 0x9db565fa100ad34b, 0xf5ac6c064d16d7d0
    .dword 0x83c6ad4cc578d3ad, 0x58c6a31136deb672
    .dword 0x8d82d9e21ebc94c8, 0x4f137bdfae9a3798
    .dword 0x789e1f0424fcdd63, 0x315ec164006c8683
    .dword 0x2da8c534a05b8d59, 0x9522f52a73a8935d


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
