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
                    la x19, data0                             
                    add x18, x18, x19                         
                    fld f0, 24(x18)                           
pfx.bb0.l1:         andi x21, x21, 0x3f8                      
                    la x22, data0                             
                    add x21, x21, x22                         
                    fld f1, 8(x21)                            
pfx.bb0.l2:         andi x21, x21, 0x3f8                      
                    la x19, data0                             
                    add x21, x21, x19                         
                    fld f2, 8(x21)                            
pfx.bb0.l3:         andi x20, x20, 0x3f8                      
                    la x18, data2                             
                    add x20, x20, x18                         
                    fld f3, 8(x20)                            
pfx.bb0.l4:         andi x22, x22, 0x3f8                      
                    la x18, data4                             
                    add x22, x22, x18                         
                    fld f4, 16(x22)                           
pfx.bb0.l5:         andi x19, x19, 0x3f8                      
                    la x18, data6                             
                    add x19, x19, x18                         
                    fld f5, 16(x19)                           
pfx.bb0.l6:         andi x22, x22, 0x3f8                      
                    la x20, data2                             
                    add x22, x22, x20                         
                    fld f6, 8(x22)                            
pfx.bb0.l7:         andi x19, x19, 0x3f8                      
                    la x18, data4                             
                    add x19, x19, x18                         
                    fld f7, 8(x19)                            
pfx.bb0.l8:         andi x20, x20, 0x3f8                      
                    la x21, data2                             
                    add x20, x20, x21                         
                    fld f8, 16(x20)                           
pfx.bb0.l9:         andi x20, x20, 0x3f8                      
                    la x22, data1                             
                    add x20, x20, x22                         
                    fld f9, 24(x20)                           
pfx.bb0.l10:        addi x18, zero, 660                       
pfx.bb0.l11:        addi x19, zero, 664                       
pfx.bb0.l12:        addi x20, zero, 1260                      
pfx.bb0.l13:        addi x21, zero, 950                       
pfx.bb0.l14:        addi x22, zero, 38                        
pfx.bb0.l15:        addi x23, zero, 1527                      
pfx.bb0.l16:        addi x24, zero, 1952                      
pfx.bb0.l17:        addi x25, zero, 1961                      
pfx.bb0.l18:        addi x26, zero, 1641                      
pfx.bb0.l19:        addi x27, zero, 1925                      
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
prp0.entry.l9:      nop                                       
prp0.entry.l10:     nop                                       
prp0.entry.l11:     divw x20, x21, x18                        
prp0.entry.l12:     feq.s x22, f2, f0                         
prp0.entry.l13:     fcvt.d.w f3, x21                          
prp0.entry.l14:     call fn2                                  
prp0.entry.l15:     fmul.s f0, f3, f2, rmm                    
prp0.entry.l16:     bgeu x21, x20, prp0.bb0                   
prp0.bb0:
prp0.bb0.l0:        fmul.d f1, f3, f4, rmm                    
prp0.bb0.l1:        fclass.d x18, f1                          
prp0.bb0.l2:        sll x21, x20, x19                         
prp0.bb0.l3:        srliw x22, x18, 13                        
prp0.bb0.l4:        addiw x18, x22, 819                       
prp0.bb0.l5:        srliw x20, x22, 11                        
prp0.bb0.l6:        jal x19, prp0.bb1                         
prp0.bb1:
prp0.bb1.l0:        slli x21, x19, 21                         
prp0.bb1.l1:        fle.s x19, f4, f1                         
prp0.bb1.l2:        or x18, x21, x20                          
prp0.bb1.l3:        call fn3                                  
prp0.bb1.l4:        call fn4                                  
prp0.bb1.l5:        sltu x18, x19, x21                        
prp0.bb1.l6:        fcvt.d.s f3, f3                           
prp0.bb1.l7:        beq x18, x22, prp0.bb3                    
prp0.bb2:
prp0.bb2.l0:        fsub.d f2, f1, f4, rmm                    
prp0.bb2.l1:        fsub.s f2, f3, f4, rdn                    
prp0.bb2.l2:        and x19, x18, x21                         
prp0.bb2.l3:        xori x22, x21, 927                        
prp0.bb2.l4:        call fn3                                  
prp0.bb2.l5:        call fn4                                  
prp0.bb2.l6:        fmv.x.w x18, f4                           
prp0.bb2.l7:        srl x20, x18, x21                         
prp0.bb2.l8:        bne x20, x21, prp0.exit                   
prp0.bb2.l9:        fmadd.s f0, f1, f3, f4, rdn               
prp0.bb2.l10:       beq x19, x21, prp0.exit                   
prp0.bb3:
prp0.bb3.l0:        call fn4                                  
prp0.bb3.l1:        fsgnjx.s f1, f0, f3                       
prp0.bb3.l2:        xori x21, x22, 1568                       
prp0.bb3.l3:        la x19, prp0.exit                         
                    jalr x22, 0(x19)                          
prp0.bb3.l4:        fcvt.d.wu f1, x18                         
prp0.bb3.l5:        blt x18, x22, prp0.exit                   
prp0.bb3.l6:        fsgnj.d f1, f2, f0                        
prp0.bb3.l7:        fmin.s f4, f1, f2                         
prp0.bb3.l8:        addi x22, x21, 1196                       
prp0.bb3.l9:        bne x19, x20, prp0.exit                   
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
prp1.entry.l9:      nop                                       
prp1.entry.l10:     nop                                       
prp1.entry.l11:     fcvt.wu.s x20, f2                         
prp1.entry.l12:     la x22, prp1.bb3                          
                    jalr x21, 0(x22)                          
prp1.entry.l13:     fclass.s x21, f2                          
prp1.entry.l14:     andi x21, x19, 1070                       
prp1.entry.l15:     call fn2                                  
prp1.entry.l16:     mulhsu x22, x19, x20                      
prp1.entry.l17:     fcvt.d.l f2, x19                          
prp1.entry.l18:     fnmsub.d f3, f2, f1, f0, rmm              
prp1.entry.l19:     beq x19, x21, prp1.bb0                    
prp1.bb0:
prp1.bb0.l0:        mulw x19, x22, x20                        
prp1.bb0.l1:        call fn3                                  
prp1.bb0.l2:        call fn3                                  
prp1.bb0.l3:        fcvt.lu.s x19, f0                         
prp1.bb0.l4:        fcvt.w.d x22, f4                          
prp1.bb0.l5:        la x22, prp1.bb1                          
                    jalr x19, 0(x22)                          
prp1.bb1:
prp1.bb1.l0:        fcvt.lu.s x19, f0                         
prp1.bb1.l1:        call fn1                                  
prp1.bb1.l2:        fcvt.l.d x19, f2                          
prp1.bb1.l3:        fcvt.d.wu f0, x19                         
prp1.bb1.l4:        fsgnjx.s f1, f4, f3                       
prp1.bb1.l5:        fnmadd.s f2, f1, f4, f0, rtz              
prp1.bb1.l6:        bltu x21, x18, prp1.bb2                   
prp1.bb2:
prp1.bb2.l0:        call fn3                                  
prp1.bb2.l1:        mulw x19, x21, x20                        
prp1.bb2.l2:        fsgnjn.s f3, f1, f2                       
prp1.bb2.l3:        beq x18, x19, prp1.exit                   
prp1.bb2.l4:        fsgnj.d f0, f1, f4                        
prp1.bb2.l5:        sra x20, x21, x18                         
prp1.bb2.l6:        fsgnj.d f3, f1, f4                        
prp1.bb2.l7:        jal x19, prp1.exit                        
prp1.bb3:
prp1.bb3.l0:        call fn3                                  
prp1.bb3.l1:        fence.i                                   
prp1.bb3.l2:        jal x20, prp1.exit                        
prp1.bb3.l3:        blt x20, x19, prp1.exit                   
prp1.bb3.l4:        fsub.d f4, f0, f3, rdn                    
prp1.bb3.l5:        slt x22, x18, x20                         
prp1.bb3.l6:        call fn1                                  
prp1.bb3.l7:        fmul.s f4, f0, f2, rdn                    
prp1.bb3.l8:        fsgnjn.s f2, f4, f3                       
prp1.bb3.l9:        remw x21, x19, x20                        
prp1.bb3.l10:       jal x18, prp1.exit                        
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        fmsub.d f1, f4, f0, f2, rup               
tc.entry.l1:        fsub.s f2, f1, f3, rmm                    
tc.entry.l2:        fsgnjn.s f1, f4, f0                       
tc.entry.l3:        mul x18, x18, x30                         
tc.entry.l4:        fmadd.s f2, f1, f4, f3, rup               
tc.entry.l5:        fmv.x.w x21, f2                           
tc.entry.l6:        call fn4                                  
tc.entry.l7:        andi x21, x21, 0x3f8                      
                    la x20, data2                             
                    add x21, x21, x20                         
                    lb x18, 30(x21)                           
tc.entry.l8:        fle.d x20, f2, f4                         
tc.entry.l9:        mul x19, x19, x30                         
tc.entry.l10:       fclass.d x19, f0                          
tc.entry.l11:       bgeu x22, x19, tc.bb0                     
tc.bb0:
tc.bb0.l0:          andi x22, x22, 0x3f8                      
                    la x18, data6                             
                    add x22, x22, x18                         
                    amominu.w x19, x20, (x22)                 
tc.bb0.l1:          mul x19, x19, x30                         
tc.bb0.l2:          feq.s x21, f4, f3                         
tc.bb0.l3:          fmv.x.d x20, f0                           
tc.bb0.l4:          mul x20, x20, x30                         
tc.bb0.l5:          andi x18, x18, 0x3f8                      
                    la x20, data3                             
                    add x18, x18, x20                         
                    fsd f0, 16(x18)                           
tc.bb0.l6:          sraiw x20, x19, 17                        
tc.bb0.l7:          la x18, tc.bb1                            
                    jalr x22, 0(x18)                          
tc.bb1:
tc.bb1.l0:          mul x18, x18, x30                         
tc.bb1.l1:          fnmsub.s f2, f3, f0, f4, rtz              
tc.bb1.l2:          mul x19, x19, x30                         
tc.bb1.l3:          call fn0                                  
tc.bb1.l4:          andi x19, x22, 850                        
tc.bb1.l5:          mul x18, x18, x30                         
tc.bb1.l6:          andi x18, x18, 0x3f8                      
                    la x20, data3                             
                    add x18, x18, x20                         
                    amoxor.w x19, x21, (x18)                  
tc.bb1.l7:          andi x21, x21, 0x3f8                      
                    la x20, data5                             
                    add x21, x21, x20                         
                    sh x19, 26(x21)                           
tc.bb1.l8:          andi x20, x20, 0x3f8                      
                    la x18, data5                             
                    add x20, x20, x18                         
                    lw x22, 24(x20)                           
                    spdoc_check_d
transient:
transient_end:
tc.bb1.l9:          blt x20, x18, tc.exit                     
tc.bb2:
tc.bb2.l0:          sll x18, x22, x20                         
tc.bb2.l1:          andi x19, x19, 0x3f8                      
                    la x18, data2                             
                    add x19, x19, x18                         
                    amoadd.d x20, x21, (x19)                  
tc.bb2.l2:          andi x22, x22, 0x3f8                      
                    la x21, data2                             
                    add x22, x22, x21                         
                    sb x20, 5(x22)                            
tc.bb2.l3:          andi x22, x22, 0x3f8                      
                    la x19, data6                             
                    add x22, x22, x19                         
                    lbu x20, 19(x22)                          
tc.bb2.l4:          mul x21, x21, x30                         
tc.bb2.l5:          call fn4                                  
tc.bb2.l6:          andi x22, x22, 0x3f8                      
                    la x18, data7                             
                    add x22, x22, x18                         
                    fsd f4, 24(x22)                           
tc.bb2.l7:          mul x18, x18, x30                         
tc.bb2.l8:          fnmadd.d f3, f0, f2, f1, rdn              
tc.bb2.l9:          bgeu x18, x20, tc.exit                    
tc.bb2.l10:         mul x19, x19, x30                         
tc.bb2.l11:         mul x22, x22, x30                         
tc.bb2.l12:         andi x19, x19, 0x3f8                      
                    la x22, data0                             
                    add x19, x19, x22                         
                    amoor.d x18, x21, (x19)                   
tc.bb2.l13:         bne x22, x21, tc.exit                     
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
fn0.entry.l0:       fcvt.lu.s x27, f9                         
fn0.entry.l1:       lui x25, 349                              
fn0.entry.l2:       fcvt.s.l f7, x23                          
fn0.entry.l3:       srliw x27, x23, 19                        
fn0.entry.l4:       flt.s x23, f7, f5                         
fn0.entry.l5:       fsqrt.d f5, f9, dyn                       
fn0.entry.l6:       fcvt.wu.s x25, f8                         
fn0.entry.l7:       fmsub.s f7, f8, f5, f9, rup               
fn0.entry.l8:       fmax.d f5, f7, f9                         
fn0.entry.l9:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       fdiv.d f9, f7, f6, rtz                    
fn1.entry.l1:       fsqrt.s f8, f5, rmm                       
fn1.entry.l2:       slliw x27, x25, 22                        
fn1.entry.l3:       fcvt.wu.s x26, f5                         
fn1.entry.l4:       fmv.w.x f5, x25                           
fn1.entry.l5:       srli x26, x25, 2                          
fn1.entry.l6:       remu x26, x25, x24                        
fn1.entry.l7:       ori x23, x24, 1564                        
fn1.entry.l8:       fsqrt.d f7, f5, dyn                       
fn1.entry.l9:       mulhu x26, x27, x25                       
fn1.entry.l10:      ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       srai x25, x27, 32                         
fn2.entry.l1:       fmv.x.w x27, f8                           
fn2.entry.l2:       and x27, x24, x25                         
fn2.entry.l3:       fcvt.w.s x26, f6                          
fn2.entry.l4:       fdiv.d f8, f6, f7, rtz                    
fn2.entry.l5:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       divw x24, x23, x27                        
fn3.entry.l1:       div x26, x24, x25                         
fn3.entry.l2:       rem x24, x27, x26                         
fn3.entry.l3:       fmv.x.w x26, f5                           
fn3.entry.l4:       fmul.d f5, f7, f6, rdn                    
fn3.entry.l5:       sltiu x27, x24, 1778                      
fn3.entry.l6:       fcvt.s.lu f8, x26                         
fn3.entry.l7:       ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       fmsub.s f7, f9, f5, f6, rmm               
fn4.entry.l1:       fmax.s f7, f5, f6                         
fn4.entry.l2:       fcvt.lu.s x26, f9                         
fn4.entry.l3:       slti x25, x23, 1357                       
fn4.entry.l4:       fsqrt.s f9, f8, rtz                       
fn4.entry.l5:       rem x27, x26, x23                         
fn4.entry.l6:       fcvt.lu.d x26, f5                         
fn4.entry.l7:       add x27, x26, x24                         
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
    .dword 0xd3a992fc8dd4db4e, 0xee84fbe10e7e84ae
    .dword 0x16e0fcf0d43aa8ac, 0x4aada9146260943b
    .dword 0x1af1683003365cde, 0x43298beb06cbabda
    .dword 0xf0788c161b6cc28e, 0xab1aecc3150bbbc5
    .dword 0x1d462fd77cbb40d4, 0x53761b47e1d5da67
    .dword 0x6cf2f15e9df41d2e, 0x45ee7efa9cf921dc
    .dword 0xe61be2f917e77857, 0x640b7f978a65f9eb
    .dword 0xbe9c0e6219d4dd76, 0x4a4041d8dc09ce3
    .dword 0x151925cebe71b035, 0x853bcc449906a1ec
    .dword 0x84d74d487ce64e6a, 0x86a2e3c26196c9ec
    .dword 0x2c338a103a403de1, 0x80d5dc196ce6250f
    .dword 0xe2438d5e294f9401, 0x87d86661659332f6
    .dword 0x7483d209231078f7, 0xc8673088e230e81
    .dword 0x133e708364f84295, 0xec0369be1047ded7
    .dword 0x8b2dd13f1d8d634c, 0x1dc915997d7aeeb3
    .dword 0x45316e3e80a98b29, 0xc672ecfd5d1b8156
    .dword 0x8a15ad6b84045254, 0x3ace0ed6caafe3c0
    .dword 0xf28c7b78a9c5e5dc, 0x6b34fc3f687b317d
    .dword 0x74373f85e1db88f2, 0xcdd5864288e67dbd
    .dword 0x4383643e71a80503, 0x99ec41cf52ac1063
    .dword 0xf30e23ea8e09d0de, 0x19893322b70e765c
    .dword 0xc9f00e8828d9b0f4, 0x58657025777156aa
    .dword 0xd22d4771d40718e8, 0xba146f80bed0ee22
    .dword 0xeca390720a2d6a78, 0xed58ad502b7e6c76
    .dword 0x347f93321934f2a9, 0x9e73be209b038479
    .dword 0x907d092efcb819fe, 0xb8bb20e1f66675fe
    .dword 0x1d6bca81e640ec37, 0x103dc85887035cfe
    .dword 0x6f69a302b7781a1e, 0x38c275ec25a411a4
    .dword 0x44500e5101ec150a, 0xe2442e06b3e8ec97
    .dword 0x16a963ced416aeb3, 0xd631357db5d9035
    .dword 0xcce0cb7bfdcce98d, 0x5afaeda2ac75f5be
    .dword 0x5278330777d48a04, 0x897a2c5612bc1c67
    .dword 0x9632bad555aef9ac, 0x315e779c13a9655b
    .dword 0xfa2208f9317c107e, 0x9709f97a427dff4c
    .dword 0x9a64f11138e3d840, 0x8938bf4aa83b3d44
    .dword 0x28e578e9a799ded7, 0x5ec596bfc815df23
    .dword 0xab0a2d94a2b6da6e, 0x94eabda6d80599fd
    .dword 0xf60edc664932c120, 0x758ea3cc5c32bb6b
    .dword 0xfba85938c19d41ad, 0x2a3af8bb4b7ff278
    .dword 0xdbd914b19720e0d8, 0x6f0bbd7675cbc67a
    .dword 0x1b3b0514de9dff3a, 0x5b9a17fdd5c36416
    .dword 0x83537a9af81ca92e, 0x47ec2673bcc46b48
    .dword 0xe78e57bba4b1dd3a, 0x664eb011ae1281bf
    .dword 0xe8ab6ed91636acaa, 0x7cbe0c0968436a2a
    .dword 0xfca452c888cc53c6, 0xa88570f79f6a9d08
    .dword 0x87b49647b208d23d, 0x6b593c5576f8dcf3
    .dword 0x92c76b6fb7b011eb, 0x5410d23eb0f16163
    .dword 0x88e84ed58e2c869f, 0x37e2154700baaaec
    .dword 0x460b04bb06715d90, 0x3efb561e6c71919d
    .dword 0x80925e114267b7a2, 0x574ab36879cf730a
    .dword 0x81724fc430275529, 0xdbfe0f0bd099080
    .dword 0x295bc438a56ce8a8, 0x73cbd14838a1a88e
    .dword 0xd09459fdc6c6c604, 0x485b77c308733173
    .dword 0x7fdabf3d743369a1, 0x1c60327c70a20b3a
    .dword 0xc326a25656b43e51, 0x89dd84d444df8892
    .dword 0x4c95faf0f1868904, 0xf637e01e324deda7
    .dword 0x9b06eb2e2ec14e12, 0xe4dba8090f9e3b33
    .dword 0x458554c1133e7868, 0xa145a542b6f29132
    .dword 0xabc659ae60a5806, 0x1e9737aadb4b266f
    .dword 0x95ea7162ffbccb70, 0xfc06c271f100fc31
    .dword 0xbe04af73297f2439, 0xc107d595f081f21
    .dword 0x215aa9d759e9e977, 0xe57dc0f29cff0f77
    .dword 0x3580227f045769a9, 0x9b4608a7d9c356e6
    .dword 0xc2dbc04926e15694, 0xb9edbf689bfa0505

    .align 12
data1:
    .dword 0x473165c756cb5d88, 0x59e46289e5fa9a9b
    .dword 0xbeab5646a3b2f23d, 0x77ce6d07f047de24
    .dword 0x276771848cd9bcfd, 0x20b58793cda1882d
    .dword 0x39ec63c34ee972d5, 0x7a962dbf0e5d84a1
    .dword 0xafde686e4a16711f, 0x3e8a3a3be9ee7377
    .dword 0x4b7da6d68e524e2f, 0xfa6b25e609ccc60d
    .dword 0xb2aa557caca9627c, 0x8a89a421ebc372b5
    .dword 0x48e273827466cd2, 0x50b0bf0e14570774
    .dword 0x7db85b1d780cdaaa, 0xc37cf925a3127c1a
    .dword 0x536b940b2fffa248, 0x96d928061d26c2ae
    .dword 0x68528751b20bb595, 0x4628aff4eb785919
    .dword 0x7704f8a8432ccdc2, 0x75c4eee9264d1e03
    .dword 0x98001fa351867a5e, 0x326235345d33e207
    .dword 0x7f4774b43310403b, 0xfe2a6b6308092a63
    .dword 0xe69b248acb106e15, 0x1813fee29736a4c6
    .dword 0x74fbea8e9719f4ed, 0x53fbdcaf4ac27d74
    .dword 0x48cc0aa782c58f74, 0xbc636d60f4c8aaa3
    .dword 0x6b7068f104874583, 0x624a81a8bfd5b597
    .dword 0xe047e5605f211d02, 0xf2859c2f5fe32f47
    .dword 0xd49f229785117cab, 0xe30ef135cbe9d2bf
    .dword 0xf201023ad473264f, 0xc6d640766fbc175b
    .dword 0xfc2db39c75205263, 0x46e1947af44122fc
    .dword 0x251b39a5dcfaa1fb, 0xe7d9f4c6a502134e
    .dword 0xe6b4c9d8516227af, 0xcd227d2fa84bc34e
    .dword 0xba44f65d568f6043, 0xf4f62223cf35009b
    .dword 0x44b37833c0e82965, 0x6053c7734db31525
    .dword 0x6c4007986ca92f34, 0xe8c7aa0403c2a41b
    .dword 0x9509831ea2d2fef5, 0x2708b56e18ec9d86
    .dword 0x3f4bdc2d08ab008, 0x94bbf54a8855693e
    .dword 0xe3b93cec33393fc8, 0x658cdc261c5c1426
    .dword 0x400ae60c2506949f, 0x69909ce4037633cb
    .dword 0xacbbbf1898e052ef, 0x7fa2a6ad280563f3
    .dword 0x4900e7f3087daf2e, 0x7917466f95a51840
    .dword 0xdff0337ab18b1051, 0xab1c7eaef479711f
    .dword 0x3950ca5d8b94f110, 0x547b7f0397973ac3
    .dword 0x78951fbfe87707bb, 0xf34596838db79a0d
    .dword 0xb0473bcd38d36d3, 0x165fbeaf390e0a92
    .dword 0x85991b18fcffd1ab, 0x932495863c6aec01
    .dword 0x6ba7f60a2ea033cd, 0x203e4dd8d7a2e184
    .dword 0xcbbf7c8c85245196, 0x3d404cd512f20277
    .dword 0x85ddbcd0c2b968dc, 0x13c3af380964de35
    .dword 0x5ed10d63e123618, 0x3b69c99aec229828
    .dword 0xa05d9b1fdfffb3a2, 0x11504248d04e58d0
    .dword 0xc1f0a8045da21fa4, 0x55c9646c28a0eb81
    .dword 0xca9cc32835073b4a, 0x1a849fc7fe1845a5
    .dword 0x4c2b0f994e5cfe13, 0x44e9867670b15af9
    .dword 0x4fcd9f4b89651f, 0x17706c2c5749b5b8
    .dword 0xd66fb135b14d44d3, 0x91127635327398dd
    .dword 0x75896b6913978276, 0x1c483dd49de46b76
    .dword 0x437b731f9b3b718f, 0xf7d43d8b0b8fa9eb
    .dword 0x7062469a661c799d, 0x3463e3867b608402
    .dword 0xe5776e385a796e1a, 0x6f53330dc8547015
    .dword 0x2b191b1ec6afc9b, 0x3a3df27c8f3d8c14
    .dword 0xb5f80bc9ba9dbe44, 0x14e61f085fe0e095
    .dword 0x7c83b072d1698893, 0xd76f6c9df1719fb2
    .dword 0x84222805d542f570, 0x20602f281a545c7e
    .dword 0x12b9077c6f9836bd, 0x54bd243c89f499a2
    .dword 0xb6feb7a35fa45e86, 0xc21908d184816ca3
    .dword 0xe8438314c09642b0, 0xa404f66d0304b005
    .dword 0xd3422250f322af5f, 0x70d2a2ed184defc9
    .dword 0xa3b4487a4fd67d74, 0xd80c7ce74a8436fc
    .dword 0xd26c3691546259b8, 0xe6359104a1fc6d
    .dword 0x5b6eaed74f8e1c94, 0x1746d86bad3a70e2
    .dword 0x28dc90e109ff3e4f, 0x55020f3e3ae68e29

    .align 12
data2:
    .dword 0x7b539f2f65bf06a0, 0x714d18625132e4a2
    .dword 0xc8df2ab71d0507fb, 0x767923c1b3723eed
    .dword 0x64dfe7dcb8a61d68, 0x7652365c4b5abcf9
    .dword 0xce43007237a037dc, 0xa2e278ab2c526f79
    .dword 0xeb06ebd740ef4b6f, 0xabb7d82c79a08119
    .dword 0x5db46fcf329275e2, 0xa58b907bd61c00f0
    .dword 0x71032af9f53ae647, 0x1b1e5362c163d74d
    .dword 0xaf4db924099e4909, 0xef10246153ea2c75
    .dword 0x4507d00101c22a00, 0xebba68d9b4330ba6
    .dword 0x1458e87599afae8b, 0x678d6cb3cba292bf
    .dword 0x3cc7bf12e2e8d47a, 0x172c2310cd353479
    .dword 0x45ed0923835cb85b, 0x21e5921d6d6b0ee8
    .dword 0x15a410bd8677348d, 0x37b4fee61b958597
    .dword 0xc2170e3846b358f0, 0x8002da45065bdd5d
    .dword 0xc2c9facb53b5bd30, 0xf887f48232a3259f
    .dword 0xd7154bed0f6a3abd, 0x7b937e945cb2406f
    .dword 0x642727a74f7fb43f, 0x778f267d98e9df3d
    .dword 0x339fbf6e82e6ee52, 0x426b8adcd9e298c0
    .dword 0xc8205be5749025c4, 0xa1285f6545e6fa35
    .dword 0x3f962b530cc7004b, 0xefab38c3a9aab04
    .dword 0x9b30f66029dcf9a2, 0x6416fa7462ac7bb2
    .dword 0x512122dcee2cff30, 0xc2e8b17dbb507cf1
    .dword 0xa6284b314a36ccce, 0xcb11e267b8b5fd24
    .dword 0x223dac7f82f218cb, 0x465e0cc2b9ad8839
    .dword 0xfc71bb5509637188, 0xba3412f55f9ef08e
    .dword 0x1a6431746a16fbc1, 0xd41ae9aa8295b211
    .dword 0xfebfa41f9dc3f946, 0xdd3b35df9fe27603
    .dword 0xe6d2888d3237bc08, 0x6eaf78320eac45c
    .dword 0x59017e3c3a1349bf, 0xa5cfa5c59360dbb2
    .dword 0x8be3a8bb35873ef7, 0xdd21dd79881616ec
    .dword 0xc6461f4c3d139bf2, 0x9be726863acea0aa
    .dword 0xef53ead2de6735e2, 0x5599a26529aaa8f8
    .dword 0x8e906491a0072f05, 0x3476d755b609c74b
    .dword 0x78414e68b0b33970, 0xf72fc05dd97d2c88
    .dword 0x57e606ae9e867fad, 0x2387598edcb74410
    .dword 0x443f647be125878f, 0x54247f63b6b825a8
    .dword 0xbb4bc7b65f41ad9f, 0x722ec973997e1271
    .dword 0x5ec25dcd8077b3a5, 0xc00901ea2ab685c2
    .dword 0x3be99556a5e0d2a, 0x4f919696fb7a1834
    .dword 0x8e99fa8a81e55138, 0xd6cafd01779633dd
    .dword 0xc07a812c62c2b22c, 0x8ad938cfd133132d
    .dword 0xa806ebd655795b90, 0x38bd4aa72fc0da45
    .dword 0x9a0f1380ce743bb9, 0x13c4f08c0fff4475
    .dword 0xfe96a35378354456, 0xd1cb82cbefad6db6
    .dword 0x960b3d8d1c50e937, 0xf9e6a96eba1e7e08
    .dword 0xc5fadf597192beb, 0xda55bb9486aeaf16
    .dword 0xff7357203c1eccfb, 0x31d9ed5037228704
    .dword 0x128b68d40ff48576, 0xbee233025e5fe825
    .dword 0x55dc76147cab2ee3, 0xfa8837644baaf047
    .dword 0x3bbefd0c1e76f15b, 0x42356490da2642b
    .dword 0x2ef37c0558a9f021, 0x8f23a07ef401771c
    .dword 0xac84f807dd91c958, 0x13c5b24989cc912c
    .dword 0x22012f84d99ca4d0, 0xed5c8ee06acd89f1
    .dword 0xdb2747148a36a10d, 0xe5bc473d004afa54
    .dword 0x7c9a6b8f337593f1, 0xa68c163d453f32e
    .dword 0xb9c0f8f7e7f277ad, 0xece61a9ebad5bebc
    .dword 0xd969fa961477914e, 0xf48f1c2bffd4e558
    .dword 0xa3f732b85547972e, 0xa3248d203351553f
    .dword 0xd8ad46b79a56f1f9, 0xa880e54590db8413
    .dword 0x3b4ae7c311c43b80, 0x7a5f71bf7daa2f21
    .dword 0xe8ee51625072e09e, 0x795eaac6d6ca9a48
    .dword 0xf68a02f19c005201, 0x9588387830f406c1
    .dword 0xda9b6f78c844ee32, 0x1dd74e8ce8ab95b
    .dword 0xf77a6887e777d633, 0xc7f494105d66e305

    .align 12
data3:
    .dword 0x8001b8c536771460, 0xa892022f600fe3c5
    .dword 0xe32e2624976c3b99, 0x78426eb9ec869d32
    .dword 0x1b7e3840fe55b8e7, 0x40bfa38678e08615
    .dword 0xbcdfb86b22d5a48d, 0xb025b3d2dd058010
    .dword 0x7932e15fe66e9076, 0x724fd0a1aff5e53c
    .dword 0x30626e592a1de090, 0x386a2cc14e47f1e
    .dword 0x2309dd04fd51e047, 0x7480126e30f3bbaa
    .dword 0x167497e12153dfbe, 0x33b0b5e21844999c
    .dword 0x64de8a424f583e43, 0x64e7572be5804c4e
    .dword 0x43bc65eecac89f0e, 0xa39638461a27e4de
    .dword 0x4ce3389ed455d932, 0xce62eb9b274af65e
    .dword 0x5cadc21ba5d55d46, 0xbeaf3efe4a456878
    .dword 0x2eaa81154f5c3411, 0xaa019cb1f85489a
    .dword 0x681406cf6269042b, 0xe7b2ff02e3dff728
    .dword 0x7ffbfa9e129f1f38, 0xcb072b8adf470b79
    .dword 0xd887c4a258a3a874, 0x52ded8449369985
    .dword 0x70de753c4dc86a32, 0x4c13d88dc8d0c453
    .dword 0x73718e673cd62f78, 0x50470c4228836445
    .dword 0xfb809183f46a2ccc, 0x240d016cfc77f4c1
    .dword 0x37e3b3012bb192fe, 0xc6d06d0b92464993
    .dword 0x8571f521107c0c5e, 0x6cc757e8ad53b02b
    .dword 0x2949f31ff2e3ce1a, 0x7740014ef32776ad
    .dword 0xcc2b3d11fc2968c5, 0xe686ad1745435bf
    .dword 0xbd7c63a4ad6ce60d, 0x8d78c6979960c071
    .dword 0xd12f6a08b5adda67, 0x3fb65a363c9cd286
    .dword 0x82e5290d9fe5664d, 0x60b8b6e63b629d0f
    .dword 0x36c4823aaf1ca8bf, 0xd23dc510e5cd12fb
    .dword 0xf27011cfcc74fcee, 0x97b2c6486c8a7aba
    .dword 0x24e7c4e04f0d4c88, 0x5c16894a853c2702
    .dword 0x906930d71e17df7c, 0x269d53ccab0f140e
    .dword 0xe9ed938e6a4b4eb4, 0xf0e467e5db2d4ef1
    .dword 0x40890b436aadf05d, 0x9fe8102d6a9fb46a
    .dword 0x68c91af53b40bfd5, 0x7b1559e658d94e1a
    .dword 0x48e227fd0cac3c3e, 0xbe0e9207d73613b3
    .dword 0xea7b5c19d18790d1, 0xab859279a1d96973
    .dword 0xdc342af435ae0e28, 0xbb83b5ceee935114
    .dword 0xc2ac12744f08945a, 0x956e72cdb206be5f
    .dword 0x6859e682c82bf08e, 0xb225e7779514ba58
    .dword 0x4ef9a6ed554a7a42, 0xa00d4462b8b23f56
    .dword 0x3b1ec71f4fe42efa, 0x1df5befa2a076eb4
    .dword 0xd0e40277f324c026, 0x97f20eaa14fb4c53
    .dword 0x474abf5df135fb88, 0x93936df39ab45480
    .dword 0x42e84d66585e553e, 0xfc513fd349cddf0c
    .dword 0x89bb23493471d5, 0x6325e96e9218af91
    .dword 0x4b400941cf38936d, 0xb386ee604d2fd32c
    .dword 0xddea958bf75febc0, 0x9047f3385232cf0
    .dword 0xed9ac9346f1ebf1a, 0xd3eb571bd57b3af9
    .dword 0xe7a011b6437523fd, 0x2f31fdbf21e5bb8a
    .dword 0xb29706da540496e8, 0x24c9741839441de2
    .dword 0xad52404409f646e4, 0x92584d873b2bf731
    .dword 0xde256e4423b9ca28, 0x2aa4890b9434c1f8
    .dword 0xf066a69313665a55, 0x85274a86fedee59d
    .dword 0xcb041c93b4ba1b6a, 0x667cf283b15cdaa7
    .dword 0xfcfa9038b5076d6a, 0x182f6ea4fd9018b8
    .dword 0xd621da130a396c14, 0x46deadcfe557eeb5
    .dword 0x4c2b45035150e54f, 0xbb6e3e2b182514f4
    .dword 0x73c50d73d68bd666, 0xa9d4e0e9338dc656
    .dword 0xb8f81a70e2554e7b, 0x539e965d4f0d14e1
    .dword 0x7f642c0a7d24a520, 0xc027e59a1db8e91f
    .dword 0xd8597baf846e5e45, 0x98b29f8f66f9eccf
    .dword 0xde79230056dab8d1, 0x2734d77531b9c066
    .dword 0xeb6f2d723305fc02, 0xf35e40a388ad52fb
    .dword 0xe3c01c8bf48b95a3, 0x35e5ee8010fbb7d9
    .dword 0x9e9d08902cd62bf4, 0x510c27a2b3fbdca9

    .align 12
data4:
    .dword 0x35168df42ade8c20, 0xc2d0542c5a5b16ca
    .dword 0x9c6beba88e25fa5a, 0xaa79fd39e24eca07
    .dword 0xc9640d1b12de3c0f, 0xa4d0e79f91d22220
    .dword 0x20f0e4495a69e730, 0x38719f5939beae23
    .dword 0xcd2a82370f3cabab, 0x781245b8fd2b2448
    .dword 0x27e51d78bbdd8bf0, 0xdd026d77264a8e47
    .dword 0x7fd0cec991540718, 0x16ede2ed71a121d4
    .dword 0xc770c89e01b6811a, 0xf536125925fdde80
    .dword 0x3322cf041506b70e, 0xbdcc3c7440966c25
    .dword 0x6457026c8ba5bec1, 0x9407badc02fa4a89
    .dword 0xc47476a9b7c3ee53, 0x7c98dfc4b17ff380
    .dword 0x1661d87d7c42ab4b, 0x2b96bc5d7e173558
    .dword 0xa8a5e0bfcbfdb552, 0xe994896b3447f89f
    .dword 0x48b1f0e9cbf433ee, 0x1167919fd7cd5c6b
    .dword 0xb58fc91f0a8e618, 0xf00b00f0de9e52e3
    .dword 0x5ed78a9befcd7d3a, 0xc08eafe22bf67c36
    .dword 0x508f3e7ae958a9bb, 0xd025b80cd959d9a2
    .dword 0x460baed6e1b8ffd3, 0xf9a52bb5b267db77
    .dword 0x451a4c74cd25848, 0x92604610ef960753
    .dword 0x7538663985b0dc8d, 0xe4173316e6d28868
    .dword 0x3c0c7e9cd8e03adc, 0xcbb0759029ec09c9
    .dword 0xb05ca0b9965baee, 0xeec3f6fa04aefb2a
    .dword 0x8a5d4276096a938b, 0x109225d2aed4a090
    .dword 0xf65fed67de3b8477, 0xa62af9b51896b95b
    .dword 0xd92f52bda7b73526, 0xffeb9241ad03619b
    .dword 0x3220d915e695aaf4, 0xd2fce83221b0b24c
    .dword 0x84a9ae0b4abc1506, 0x77bbafe1d8bfd2dc
    .dword 0x7ff43fb72f509fa, 0xe623d25ead3e235d
    .dword 0x1cd64ead0d29a5f3, 0xea449b59407d2c5b
    .dword 0x8f472f3b88cc0cfd, 0x9c6681e9186af949
    .dword 0xa1a2a18364cbb8d0, 0xa835395fe9219db1
    .dword 0xec20e8d631372fef, 0x8d3f175c38acfbbe
    .dword 0xd2c8fcf764d995e5, 0xe63264b5918f9edd
    .dword 0xf6c63d8784500bb5, 0x9745f0870f682d98
    .dword 0xa907b7fe3d992755, 0x8143b5d6b978daed
    .dword 0x59f630fa8b9f662, 0xbd8552267b289f82
    .dword 0x80693c480ea31c23, 0x3060e6444927570
    .dword 0xecf83052baefa387, 0xa23ddad6faabb4db
    .dword 0xf197cc0385bd06e9, 0x2b8ef742992b5314
    .dword 0xafed319bb99a49fa, 0xc5d6456ac83ece78
    .dword 0xa7487575faef1e69, 0x41f7359bb6b1bd5a
    .dword 0xfaf27923629a0bb5, 0x2106434c435f2e3b
    .dword 0x672da53094fa62e1, 0x738e6f1e6a422b7c
    .dword 0x133bf88a424b1049, 0x374230cea9ecc9b5
    .dword 0x8aacb10c62e5e22, 0xf0f360aeebf37489
    .dword 0x43c178e4275524f6, 0x940fc1ba8568572
    .dword 0x5559ef4c8f49a73f, 0xa0c01ef36e5ea61a
    .dword 0x5bc527532f4d5188, 0xd2a6058f0cf38060
    .dword 0xe2391ba985d8c9b9, 0xf279a33de1403ade
    .dword 0x4296bda152dd7cf0, 0xf49b836bd253bb19
    .dword 0xd7300a7c5e0c8a4a, 0xe87fc4d2be1387fd
    .dword 0x27243e0b4ccc5bfa, 0xd0964ddbdb6b72fb
    .dword 0x258c4bf7676ececa, 0x78b2467a9ed161a7
    .dword 0x385811d626a98e4b, 0xf9e44e2422feeb3f
    .dword 0x2dd477514d334284, 0xcdd5478ae079ce6b
    .dword 0x5f1c50eed343bf23, 0x925f17507c874c1f
    .dword 0x9cae1158222f829d, 0xb5f3e0ab6b7d28b9
    .dword 0x8ce75b082c273162, 0xcc096696120179ef
    .dword 0xea935b3f899db36b, 0x62ec2b3a2396541a
    .dword 0x42835a32b18a8eef, 0x108cec82d6ab2f11
    .dword 0x22cf328688150c98, 0xefac325f68882734
    .dword 0x2e40af6bfcc7324c, 0xfd5b49977fea8ad3
    .dword 0xd57e9428e5cc5e5f, 0x673e624b9990f4e1
    .dword 0xaad9094374977fad, 0x5869ede379c5e6c0

    .align 12
data5:
    .dword 0xef246baee4baaa89, 0xa75322ceb869f675
    .dword 0x8f611093eab1646f, 0xc0ee92ecb4665936
    .dword 0xc093595b88a4d374, 0x10aba4aa6cefef1c
    .dword 0x34d18a19efbeb5c3, 0x89ac45fb1d98a8b1
    .dword 0x9bc8ecbc1d874d7, 0x51a95d01e5fc2f18
    .dword 0x99e980018ac30757, 0xb116c130ee4680cd
    .dword 0xacdffc58469a06eb, 0x513c41a3fba80265
    .dword 0xefa3ff3524666968, 0x26ce39502d179845
    .dword 0x748c930686ca5343, 0x9f5ea74d3aac6732
    .dword 0x21eaf913b266eab6, 0x4d064369ed353a9c
    .dword 0x37315b136919705e, 0x107ff4ac4a68bedf
    .dword 0x19dbf050af1dc6a1, 0x897faf57f7c65d4
    .dword 0xd70cc29a156d2dd2, 0x1b057fd45e9ff085
    .dword 0x8d8468219f3417b6, 0xbbfa4fbb6e686068
    .dword 0x444fedeb33dabbc8, 0x4d9fdd7c4a22ff2e
    .dword 0xcacf9c73fb37b141, 0x8defbcea11bb9564
    .dword 0xaeeec7a2bc8c06c0, 0x2b6d69469b938067
    .dword 0x30a8294285bf53d3, 0x2b781f2d90ed81f
    .dword 0xe09e89cff35d83d6, 0xfa378ae348cab456
    .dword 0x941a03924988f082, 0xc558e1eb74b3ecee
    .dword 0x4b5a96dcc86562f6, 0x753afa88e3e2a0fc
    .dword 0x8daa490fc73cd54d, 0xced28df73b88d11f
    .dword 0x36cd2c6c7ffacff2, 0x3febb8761131ded8
    .dword 0x509fba37e88fe8d9, 0x978ed810a8f44e5f
    .dword 0xc5e0734d0a478e3b, 0xd3678c03b9c59a27
    .dword 0xb6c65052756174fe, 0x13b3dd571174e3e6
    .dword 0xb3d385ffa8cd9110, 0x62f9e9dcc39069a1
    .dword 0x4a945c542dd76609, 0xa4721e2d9d3b7230
    .dword 0x35a03c5df5db429d, 0x235e67109560452e
    .dword 0xe92a6330df369590, 0x7154ca8f275f64de
    .dword 0xdb38bf07fb6f2806, 0xc004f5fd58dbc633
    .dword 0xfbddd0712ad43da, 0xe4f6385649537e87
    .dword 0xe941ea14b45462ab, 0x1ae99194ee1f1b80
    .dword 0x1fbf4c62d5d0ec9b, 0x72c045242b5eaf2d
    .dword 0xdd4f2439ab2054fd, 0x9ba4a960a1b25831
    .dword 0x6ce14b8bbcb680d, 0xc333bd647deec1a7
    .dword 0xc91a0f36d2d175df, 0x3ce0fceeafc92fdd
    .dword 0xaceb6f90048b7231, 0xe192591deb3e2f4c
    .dword 0xc374288d41ca309e, 0x4979e40f26721830
    .dword 0xa995a6e792e0ee64, 0x7a32586119c39fe0
    .dword 0xe43c993aca13d320, 0xc7b965398cfdbde3
    .dword 0x2941db578ee23380, 0x6e5577cb9c229b84
    .dword 0x5ab98ac9d4a35dbc, 0x4a4a7dc2fe13565d
    .dword 0x8d3d53cbf5ac16ba, 0x21e0267fab44fe04
    .dword 0x363a061d12c23326, 0xe40091685eb81052
    .dword 0x57769e4090958d17, 0x5eeb98520f909b28
    .dword 0xfd6c6b74d21846a6, 0x595a677a4c84e65d
    .dword 0xe94fd20f5cbff677, 0x860b7ec9934b5341
    .dword 0x579cb199579d4ff4, 0x3cc605016959a813
    .dword 0xa14b2f987143714f, 0xea57120d15ed7f50
    .dword 0xfb35ca5723e6c456, 0x783944634be859c9
    .dword 0x13dbb61834a9c8bb, 0x2cd5517bf70e6d15
    .dword 0xaaf7c923605bd468, 0x8564dd743547dbb
    .dword 0x3f6a59579faca6b, 0x60b8e6d8a7c54bc5
    .dword 0x61c37bb8f86db3ce, 0x3a25e38092b1c546
    .dword 0xe7d181d89a95aeac, 0x9174afb0cccbf89d
    .dword 0x7c9622333619bca8, 0x349dc411e229478f
    .dword 0xce7dbac28dad974e, 0x8212043cbf6d1fb4
    .dword 0xe6ac98de9b7cf59, 0xb3f893954818b9c9
    .dword 0x63f73d077f37d96d, 0xb14eb8df79dbd62c
    .dword 0x304f12c006832c88, 0x26a1cca07932deb3
    .dword 0x44302bf613139af3, 0x84c9f2e2b4a964b5
    .dword 0xf35880f1c5f26e82, 0x44426ec430719619
    .dword 0x9505957ed7fb3bed, 0x24c5487de331ddd7

    .align 12
data6:
    .dword 0x3b73b5eaa9953707, 0x2f2b0aea2b9b37b4
    .dword 0xcbd74943934c5c5b, 0xd19cab25b5adf172
    .dword 0x27342277d1ce96e, 0x591acbc9136acc76
    .dword 0xff81965669856621, 0x4993584feab9c439
    .dword 0x6d95cc1b681a2481, 0xb4306808aa7850fd
    .dword 0xa582d5d8099b6e87, 0xf7905c0fcd6cd792
    .dword 0xfce89a4ca771b113, 0xcef3d3be7ee2ced1
    .dword 0x53f2673a9df604cd, 0xae8aa7b6c5213c74
    .dword 0xa85940abd3d15eb7, 0xe1fa03525d018ab6
    .dword 0x36508e75cf96bd15, 0x427f86995eb1f724
    .dword 0x5baf1367afab2b9, 0x890366fb3089e9fd
    .dword 0x775e441ac64dc33f, 0x9288f8191d294585
    .dword 0xaf5ae096607515e1, 0x1c7377a40f65f303
    .dword 0xb35a8d3d55322f31, 0x1a01865bf8622e27
    .dword 0x43c8c5158858d0ca, 0xfc52ff1409b384df
    .dword 0xac13bdd66874c47a, 0xffd4bd2a926a5219
    .dword 0xdb67fed8ddd7c3, 0x80853945badc2b10
    .dword 0x4e11b332818666d8, 0x71620305ae8ad08e
    .dword 0x73194e859ffdec00, 0x8a67a9f43a51cdf1
    .dword 0x2f7f348eb32a8c29, 0x8b340caf4bbc5086
    .dword 0x48dad2fc94aaf137, 0x87a7477a4dcc93d2
    .dword 0xc6761c54a11f289, 0x253e630b4b88da87
    .dword 0x296a9f3ae2f5c6c8, 0xa52386c08efd8f85
    .dword 0x641d5967cc7ff977, 0x4b22034d3b984be7
    .dword 0x5b0f65f5e163a8b4, 0xec749898c56021e0
    .dword 0x72b9099b992c6c32, 0x57330020d44cdb27
    .dword 0x6c9d82e13c1d20ad, 0xcabe4690c2d0b555
    .dword 0xba11e2009f552897, 0xf644d69f8ff17b2c
    .dword 0x31f0a23e9bde81fa, 0x1cf3f11a0c857682
    .dword 0xd14512244d5807e5, 0x76d9b3e0e8414995
    .dword 0x8df5e6bf6ffb1e87, 0x804817aeb6c89c20
    .dword 0x9d0833cfd76aa0dd, 0x86c1812476978a3d
    .dword 0xafa509252e65b8c8, 0x6fccb32e808a8b4b
    .dword 0xec672d5fabd60358, 0xd7c3357debc0304c
    .dword 0xa8d6500495718b62, 0xe23f1c6a41ff908
    .dword 0x60d79405695b26e5, 0xad3c7be804664378
    .dword 0x702df9af09c17dc, 0xb378ba08a7ffba10
    .dword 0xd48c302e481a67e6, 0xb0113cfefaf426b
    .dword 0x904315841b3696ca, 0x99a1396b6484452a
    .dword 0x6e12c8221f81aaff, 0xf14c6bea7c5726
    .dword 0x92aee7ef0d426cdb, 0xa493f207d093a7fa
    .dword 0xad83150340516c89, 0x14987506ce51c597
    .dword 0x594777df8fa3bf2a, 0x43b1e889347fefff
    .dword 0x2d2cff6b9b0d30f0, 0xbe876d969c723974
    .dword 0x2f5e2be1eeae2417, 0x116246e59b864cfe
    .dword 0x6cbcf8d8801b4ccf, 0xff032c98b3454eb8
    .dword 0xefae9e5e0f573f53, 0xc8e6a93868730271
    .dword 0x892dc2e99f23b7c6, 0x261e8102946ff9dd
    .dword 0x7d39fd6b0dee40b3, 0xd9a3954fe48ee50c
    .dword 0x7925e6a93d68f761, 0x61400c48255d6834
    .dword 0xb6434a1f5a39f61, 0x2809045a90b6c3f4
    .dword 0xa1403c7458d1d27a, 0x5744a82bcaf19221
    .dword 0x6016c06385c9d9b5, 0xeff2969c72044348
    .dword 0x1123b478e1f0dbc4, 0xed7964f9c0cec9d4
    .dword 0x65115ce31b9d5bef, 0xb38511601fe0dd9e
    .dword 0xdd346f71c7e08fe4, 0x764021aec449ae15
    .dword 0x10a299bb16749789, 0x1830490b776ad1a5
    .dword 0xa8f40c1aae78d062, 0xcfa4addeb4026b42
    .dword 0x74cf2f8537f36a2b, 0xdbba3f8d4309a76b
    .dword 0x157e2a1b42763231, 0xd0bb390075b3d634
    .dword 0xb8705dd03e911c06, 0x140f59af8086d5b4
    .dword 0x7e946db137ed361b, 0x20bf801a5b4ea8ff
    .dword 0xeebc453cd6ef032e, 0xb55c18bb04f0800e
    .dword 0x34dbed795f1401ee, 0x9316c02dd15127af

    .align 12
data7:
    .dword 0x3450ded977975c3e, 0x7a700b1de8016a1
    .dword 0xa711b5299cf81905, 0x2aa77904f4f9939f
    .dword 0x245361578b6bb9be, 0x2190b5862e38c609
    .dword 0x469219b103346e32, 0xd79f40e83c195b39
    .dword 0x23af17ffe291575, 0x4868806b243d8e87
    .dword 0x3a711385adcb0db8, 0x1d4e06483a066e66
    .dword 0xcbadb62fe1b670a, 0x329d8f09e217f8e3
    .dword 0x7a3bb78db4ca68ea, 0x446b27a9318fcdaa
    .dword 0x33a2cfb9da3413df, 0x56b84e3c4f94a749
    .dword 0x4dac1e0d44431188, 0x967b5b6e0fdf87aa
    .dword 0xe971cdb849446fc1, 0x9e0e1214390e8ddb
    .dword 0xc26bafc99f53e7c8, 0x27dbaa9734fe0105
    .dword 0xba8cd04bee1390a1, 0x2699631e70fe8d16
    .dword 0x98ff13044da6ed82, 0x5c715682e7c1b229
    .dword 0x7dbc133c082842c9, 0x7fa4d83a1a6b0232
    .dword 0x43a3680c094fb82e, 0x348c5ae7568c0d86
    .dword 0x4390bd37e0b80344, 0xe44a0276ca2d5da
    .dword 0xbe6809b5c6bcc893, 0x300b9b75f4af1b9c
    .dword 0x6cfd0ea6900ebfa3, 0xb10c0161234ac47d
    .dword 0xd76d363a382af713, 0xcee26783971d99fe
    .dword 0xf9f3bb9403609caf, 0x908ae91db81da7a
    .dword 0x8e5bbb50af869c75, 0xf0ce9da597da92be
    .dword 0xb3b4a78a48f0d8d8, 0x10742185a77d4b9e
    .dword 0xfa4cf3a0230522a2, 0xd48022bef8e85e29
    .dword 0xc16cf134e7c88a10, 0x61b59ee6df218641
    .dword 0x723afa4a7ba88eca, 0x5ed3586cde622acb
    .dword 0xcfcab4f8d518d28, 0xefe0ec519400ddb7
    .dword 0x8dc0b8c5a0425d67, 0x88dea8bec3eb8a63
    .dword 0xfee20d00be049ec0, 0xde874f9ffda05406
    .dword 0xbc8c739d4db5785d, 0x7b3583a39bd5a9b
    .dword 0xb20dd7c402c4185d, 0x74aef3fffa0f58b0
    .dword 0xb178aadcf3c20651, 0xc705c4e97e0db912
    .dword 0xb8a9cdb110a82bf4, 0x4610a77b7689848b
    .dword 0x2993effe4908001f, 0xf9a2dd4b967f258
    .dword 0xb1af1a128c70719e, 0xec886ab46f53f732
    .dword 0x7c2dbc14d69f9284, 0x7f952093d32d8470
    .dword 0xb3e584b870b8764b, 0xdadac71e3e6f7c3
    .dword 0x548b71febc2f7b89, 0xb49c8874e2a9d567
    .dword 0xda8263cdacae3002, 0xab5b4a72a335a944
    .dword 0x113f8f9b0b9500ab, 0x3314b3c33731f4f6
    .dword 0x6df68f34d6a2d05a, 0x758f512a4e2222f2
    .dword 0x7f0a15825b0c2311, 0xb279378c1bd38f09
    .dword 0x3d25d8fa58f233a2, 0x4c07d6f1ffeb932a
    .dword 0x47bd544f1452ec17, 0x7e7cb6d9116d5ccf
    .dword 0xfc7299fa6fb68612, 0x14c224d4ba439fd2
    .dword 0xe8d598be8755cb8, 0x874c0e191051ba03
    .dword 0xd7be44d5ef9f9c58, 0x637f84d371ec724f
    .dword 0x2c3634cf2b2e1033, 0xc1f05022737dd332
    .dword 0x332740a09c28e1df, 0x43ce55192303595f
    .dword 0x142a3cd5637f33a, 0x2ea98dbafd3cce82
    .dword 0x8b717452c4e42886, 0xe36acf1b8fcf68e1
    .dword 0x4a7968ceda631835, 0xd002d0af8020792f
    .dword 0x717b3f0849d76e2f, 0xec95da021bb8c9eb
    .dword 0x1b4b86f7852fefd7, 0xa93c3443e16fb66d
    .dword 0x637f9d68511b99b7, 0x7fdc3602c0d1ac79
    .dword 0x3e0dc54e6f30c2b3, 0xe6c9804d08f7073
    .dword 0xf3796c3559a26fae, 0x40ce5b3f605c8fd3
    .dword 0xf7ea07bb3dee7a0, 0x62d6b4ff0f11e9d5
    .dword 0x589c5ba1c30b2900, 0x26091389a488372e
    .dword 0x5cc0d0a4905be7cd, 0x3a18e1aa86eb60f2
    .dword 0xb8cf6c6046f68d2b, 0xbe1a46805562cde7
    .dword 0x3148c8e8c90dbbe8, 0x212848977309f84c
    .dword 0x4f9d62bfc4c9bb11, 0xf70f5f0aedf3cd5d
    .dword 0x3f6a78b958f56f47, 0x67acb0e3e6c666dc


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
