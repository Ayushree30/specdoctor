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
                    la x18, data1                             
                    add x22, x22, x18                         
                    fld f0, 0(x22)                            
pfx.bb0.l1:         andi x19, x19, 0x3f8                      
                    la x20, data4                             
                    add x19, x19, x20                         
                    fld f1, 16(x19)                           
pfx.bb0.l2:         andi x18, x18, 0x3f8                      
                    la x19, data2                             
                    add x18, x18, x19                         
                    fld f2, 0(x18)                            
pfx.bb0.l3:         andi x22, x22, 0x3f8                      
                    la x18, data6                             
                    add x22, x22, x18                         
                    fld f3, 0(x22)                            
pfx.bb0.l4:         andi x21, x21, 0x3f8                      
                    la x20, data0                             
                    add x21, x21, x20                         
                    fld f4, 8(x21)                            
pfx.bb0.l5:         andi x19, x19, 0x3f8                      
                    la x22, data7                             
                    add x19, x19, x22                         
                    fld f5, 0(x19)                            
pfx.bb0.l6:         andi x18, x18, 0x3f8                      
                    la x20, data4                             
                    add x18, x18, x20                         
                    fld f6, 24(x18)                           
pfx.bb0.l7:         andi x20, x20, 0x3f8                      
                    la x19, data7                             
                    add x20, x20, x19                         
                    fld f7, 8(x20)                            
pfx.bb0.l8:         andi x19, x19, 0x3f8                      
                    la x18, data5                             
                    add x19, x19, x18                         
                    fld f8, 16(x19)                           
pfx.bb0.l9:         andi x20, x20, 0x3f8                      
                    la x18, data0                             
                    add x20, x20, x18                         
                    fld f9, 0(x20)                            
pfx.bb0.l10:        addi x18, zero, 1906                      
pfx.bb0.l11:        addi x19, zero, 979                       
pfx.bb0.l12:        addi x20, zero, 38                        
pfx.bb0.l13:        addi x21, zero, 1878                      
pfx.bb0.l14:        addi x22, zero, 738                       
pfx.bb0.l15:        addi x23, zero, 852                       
pfx.bb0.l16:        addi x24, zero, 1339                      
pfx.bb0.l17:        addi x25, zero, 1688                      
pfx.bb0.l18:        addi x26, zero, 1470                      
pfx.bb0.l19:        addi x27, zero, 478                       
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
prp0.entry.l0:      slt x18, x21, x19                         
prp0.entry.l1:      fcvt.s.lu f1, x20                         
prp0.entry.l2:      call fn0                                  
prp0.entry.l3:      fmul.d f2, f3, f4, rne                    
prp0.entry.l4:      fadd.d f2, f3, f0, rup                    
prp0.entry.l5:      divw x18, x22, x19                        
prp0.entry.l6:      fdiv.d f0, f2, f1, rne                    
prp0.entry.l7:      fcvt.lu.d x18, f3                         
prp0.entry.l8:      fclass.s x19, f3                          
prp0.entry.l9:      flt.d x22, f0, f1                         
prp0.entry.l10:     bge x20, x22, prp0.exit                   
prp0.bb0:
prp0.bb0.l0:        call fn3                                  
prp0.bb0.l1:        slli x19, x21, 48                         
prp0.bb0.l2:        mul x19, x22, x18                         
prp0.bb0.l3:        sltu x20, x21, x19                        
prp0.bb0.l4:        call fn2                                  
prp0.bb0.l5:        call fn1                                  
prp0.bb0.l6:        rem x22, x21, x19                         
prp0.bb0.l7:        fle.s x20, f0, f3                         
prp0.bb0.l8:        blt x22, x19, prp0.bb3                    
prp0.bb1:
prp0.bb1.l0:        feq.s x18, f4, f2                         
prp0.bb1.l1:        fmax.s f0, f1, f2                         
prp0.bb1.l2:        fcvt.s.w f4, x22                          
prp0.bb1.l3:        fcvt.s.wu f4, x19                         
prp0.bb1.l4:        slt x18, x21, x19                         
prp0.bb1.l5:        fcvt.d.wu f4, x18                         
prp0.bb1.l6:        fmadd.s f2, f1, f4, f0, rtz               
prp0.bb1.l7:        fence                                     
prp0.bb1.l8:        bge x18, x21, prp0.exit                   
prp0.bb1.l9:        or x20, x21, x18                          
prp0.bb1.l10:       jal x21, prp0.exit                        
prp0.bb2:
prp0.bb2.l0:        sltiu x18, x19, 487                       
prp0.bb2.l1:        fclass.d x20, f3                          
prp0.bb2.l2:        fsgnjx.d f2, f3, f4                       
prp0.bb2.l3:        fclass.d x19, f4                          
prp0.bb2.l4:        addi x19, x22, 1107                       
prp0.bb2.l5:        fdiv.s f0, f3, f1, dyn                    
prp0.bb2.l6:        bltu x21, x22, prp0.exit                  
prp0.bb3:
prp0.bb3.l0:        call fn2                                  
prp0.bb3.l1:        bltu x19, x22, prp0.exit                  
prp0.bb3.l2:        fsgnjx.s f1, f0, f3                       
prp0.bb3.l3:        srliw x19, x20, 22                        
prp0.bb3.l4:        fmv.w.x f3, x20                           
prp0.bb3.l5:        fmadd.d f0, f2, f1, f4, rtz               
prp0.bb3.l6:        call fn0                                  
prp0.bb3.l7:        jal x21, prp0.exit                        
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      srli x19, x21, 10                         
prp1.entry.l1:      fcvt.wu.s x21, f3                         
prp1.entry.l2:      call fn0                                  
prp1.entry.l3:      fmul.s f3, f1, f4, rmm                    
prp1.entry.l4:      beq x21, x18, prp1.bb3                    
prp1.entry.l5:      bne x21, x19, prp1.bb0                    
prp1.bb0:
prp1.bb0.l0:        fsqrt.d f1, f0, rne                       
prp1.bb0.l1:        call fn3                                  
prp1.bb0.l2:        fmsub.s f2, f4, f1, f0, rdn               
prp1.bb0.l3:        fcvt.s.d f0, f0                           
prp1.bb0.l4:        fcvt.s.d f2, f2                           
prp1.bb0.l5:        fsqrt.d f2, f0, dyn                       
prp1.bb0.l6:        bltu x19, x18, prp1.bb3                   
prp1.bb1:
prp1.bb1.l0:        fnmsub.s f0, f4, f3, f1, rtz              
prp1.bb1.l1:        fnmsub.s f4, f2, f0, f1, rmm              
prp1.bb1.l2:        srli x20, x22, 26                         
prp1.bb1.l3:        fmsub.s f4, f1, f2, f3, dyn               
prp1.bb1.l4:        bltu x21, x22, prp1.bb3                   
prp1.bb1.l5:        divu x19, x21, x22                        
prp1.bb1.l6:        call fn2                                  
prp1.bb1.l7:        fcvt.wu.s x20, f1                         
prp1.bb1.l8:        fcvt.lu.s x21, f2                         
prp1.bb1.l9:        la x18, prp1.bb3                          
                    jalr x19, 0(x18)                          
prp1.bb2:
prp1.bb2.l0:        mulhsu x22, x19, x18                      
prp1.bb2.l1:        bge x20, x18, prp1.exit                   
prp1.bb2.l2:        fcvt.l.s x19, f1                          
prp1.bb2.l3:        andi x19, x18, 1988                       
prp1.bb2.l4:        bltu x21, x18, prp1.bb3                   
prp1.bb2.l5:        fcvt.s.wu f0, x22                         
prp1.bb2.l6:        xor x21, x18, x20                         
prp1.bb2.l7:        beq x22, x19, prp1.exit                   
prp1.bb3:
prp1.bb3.l0:        fcvt.d.l f4, x22                          
prp1.bb3.l1:        bltu x18, x21, prp1.exit                  
prp1.bb3.l2:        fadd.d f2, f0, f4, rmm                    
prp1.bb3.l3:        addi x20, x18, 352                        
prp1.bb3.l4:        fnmadd.d f4, f1, f0, f2, rtz              
prp1.bb3.l5:        remuw x22, x19, x18                       
prp1.bb3.l6:        fnmsub.d f3, f1, f4, f2, dyn              
prp1.bb3.l7:        bltu x20, x21, prp1.exit                  
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        sra x21, x20, x18                         
tc.entry.l1:        fdiv.d f1, f3, f4, rmm                    
tc.entry.l2:        fmin.s f4, f1, f0                         
tc.entry.l3:        divw x22, x19, x20                        
tc.entry.l4:        blt x19, x18, tc.bb0                      
tc.entry.l5:        andi x19, x19, 0x3f8                      
                    la x22, data5                             
                    add x19, x19, x22                         
                    lwu x20, 8(x19)                           
tc.entry.l6:        sltu x21, x18, x20                        
tc.entry.l7:        fcvt.d.s f1, f1                           
tc.entry.l8:        divw x22, x21, x20                        
tc.entry.l9:        call fn2                                  
tc.entry.l10:       blt x22, x18, tc.bb0                      
tc.bb0:
tc.bb0.l0:          bge x20, x22, tc.bb1                      
tc.bb0.l1:          divw x21, x22, x19                        
tc.bb0.l2:          andi x21, x21, 0x3f8                      
                    la x20, data6                             
                    add x21, x21, x20                         
                    amomin.d x22, x19, (x21)                  
tc.bb0.l3:          call fn0                                  
tc.bb0.l4:          flt.d x18, f1, f2                         
tc.bb0.l5:          divuw x19, x22, x21                       
tc.bb0.l6:          call fn1                                  
tc.bb0.l7:          andi x18, x18, 0x3f8                      
                    la x20, data4                             
                    add x18, x18, x20                         
                    amoxor.w x21, x22, (x18)                  
tc.bb0.l8:          flt.d x19, f3, f1                         
tc.bb0.l9:          call fn3                                  
tc.bb0.l10:         bgeu x22, x21, tc.bb2                     
tc.bb1:
tc.bb1.l0:          sub x20, x19, x18                         
tc.bb1.l1:          srli x22, x21, 58                         
tc.bb1.l2:          srl x18, x19, x21                         
tc.bb1.l3:          fcvt.s.w f3, x21                          
tc.bb1.l4:          call fn0                                  
tc.bb1.l5:          fcvt.lu.s x20, f3                         
tc.bb1.l6:          fmin.s f4, f3, f2                         
tc.bb1.l7:          la x20, tc.bb2                            
                    jalr x21, 0(x20)                          
tc.bb2:
tc.bb2.l0:          fsgnj.s f2, f4, f1                        
tc.bb2.l1:          fmin.s f1, f2, f4                         
tc.bb2.l2:          fmax.s f1, f4, f2                         
tc.bb2.l3:          andi x20, x20, 0x3f8                      
                    la x19, data0                             
                    add x20, x20, x19                         
                    amomin.w x22, x18, (x20)                  
tc.bb2.l4:          fcvt.w.d x20, f2                          
tc.bb2.l5:          fmadd.d f1, f2, f3, f4, rtz               
tc.bb2.l6:          divu x20, x19, x21                        
tc.bb2.l7:          call fn1                                  
tc.bb2.l8:          fsub.s f1, f4, f0, rtz                    
tc.bb2.l9:          bgeu x21, x19, tc.exit                    
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
fn0.entry.l0:       fcvt.s.l f5, x25                          
fn0.entry.l1:       fcvt.l.d x26, f5                          
fn0.entry.l2:       fsub.d f6, f8, f9, rtz                    
fn0.entry.l3:       mulhu x27, x23, x25                       
fn0.entry.l4:       divw x27, x26, x23                        
fn0.entry.l5:       fclass.s x24, f9                          
fn0.entry.l6:       fsub.s f8, f6, f9, rtz                    
fn0.entry.l7:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       fsgnjx.d f6, f8, f9                       
fn1.entry.l1:       fsgnjx.d f5, f7, f8                       
fn1.entry.l2:       remu x23, x26, x24                        
fn1.entry.l3:       flt.d x27, f7, f6                         
fn1.entry.l4:       or x24, x23, x26                          
fn1.entry.l5:       fmadd.d f7, f6, f8, f9, dyn               
fn1.entry.l6:       fcvt.d.l f7, x23                          
fn1.entry.l7:       fcvt.s.d f8, f8                           
fn1.entry.l8:       srai x24, x23, 6                          
fn1.entry.l9:       ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       fcvt.s.wu f6, x26                         
fn2.entry.l1:       fmin.s f7, f6, f5                         
fn2.entry.l2:       fcvt.s.l f8, x26                          
fn2.entry.l3:       feq.s x24, f8, f7                         
fn2.entry.l4:       fcvt.d.l f8, x26                          
fn2.entry.l5:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       srl x26, x24, x23                         
fn3.entry.l1:       sra x23, x26, x24                         
fn3.entry.l2:       fcvt.lu.s x25, f8                         
fn3.entry.l3:       fcvt.wu.s x25, f8                         
fn3.entry.l4:       fadd.s f7, f8, f9, rup                    
fn3.entry.l5:       ret                                       
fn3.exit:
fn4:
fn4.entry:
fn4.entry.l0:       divu x27, x25, x26                        
fn4.entry.l1:       fcvt.l.d x25, f9                          
fn4.entry.l2:       div x24, x26, x27                         
fn4.entry.l3:       fclass.s x24, f8                          
fn4.entry.l4:       fence.i                                   
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
    .dword 0x45315dc4c625325a, 0x32bd0de33a086465
    .dword 0x4224ab97bc46eb7d, 0x93ef98c3bee3e054
    .dword 0x78ea8948acfcba0f, 0xff9dd20afd913f76
    .dword 0x736026f5bafa0caa, 0x835013e04735f140
    .dword 0x51f1d3784a595aa3, 0xf4f6ddeb0bb45442
    .dword 0x4de34050eb7aebee, 0x91cb916d86661ce4
    .dword 0x2d752f05c13c083c, 0xfaf30dd31bd7b4fd
    .dword 0x7e027f2faf9bebbb, 0x300450ebbc60f3d5
    .dword 0x476cabd88542d8c0, 0xefe8a28b849efcbf
    .dword 0xad0839d19e5034a0, 0x6d29b1263c496498
    .dword 0x5aa78ba92ed75b0e, 0xe416e922b23bd1a
    .dword 0x75eacd39fbe58583, 0x73666da24fe3498a
    .dword 0x3e4c18d32a9a62dd, 0x4692c915608f173d
    .dword 0xdf1e341cf73316f0, 0xd67e6136af51cc72
    .dword 0x202e840c723ad161, 0xe448605441c7298e
    .dword 0x22968eaa973fa764, 0x8fa645b0662f41bd
    .dword 0x4248346c385e6428, 0xa01508fd6228dd27
    .dword 0x7793ca1f6c54f348, 0xddfb58d0d5ce5cf3
    .dword 0x82092b1b38207042, 0x707ddbb086b6d206
    .dword 0xa9517cc4eaf423b3, 0xf21b78d8de713136
    .dword 0xeb0b7031d3747586, 0x642a4866574d1e4c
    .dword 0xf376914f7539167a, 0x41d23896a9fb81c
    .dword 0xff41fe014180c749, 0x9ecafbc95077b10f
    .dword 0x51e4bb8123f7eb4f, 0xde17a3960c1607f8
    .dword 0xb6cba2689e0bd1f3, 0x65b10bcadd6bb0a8
    .dword 0x8e9b752f60defab7, 0x3d639c82985fb70e
    .dword 0x305b4291d91fc8bf, 0xb3a7befed09fabbd
    .dword 0xa6a0a721ecb3e0d5, 0x968ddece2870a76
    .dword 0x995ce125c99ce881, 0xfba39c2829b08171
    .dword 0x83d51a0f5b0c96c, 0xa04b50c03fb51a5e
    .dword 0x69a8c1a0256b905f, 0x53c1b02bb75a6cdb
    .dword 0x574eeee493ec6452, 0x970d9e71ff26e02c
    .dword 0x3f5aedef49b8537f, 0x34dda90362e864f0
    .dword 0xf01b149619296c82, 0xc91453e453e73f8e
    .dword 0x353361524c469aa1, 0x9aae4462d40498bc
    .dword 0x72471e141768ffbc, 0x30d9e81bf21131f8
    .dword 0x3b50072d1119912c, 0xcecebbd7078a1627
    .dword 0xa0bc68e3d1483ad6, 0x157d28ec6f76165c
    .dword 0x8f4e0e7d871ab800, 0xa34a3be9d1fc11aa
    .dword 0x8647cb8f5f4a7c02, 0xad0293e84652bed3
    .dword 0xcc5b1f64f64285da, 0x7248432916079ea
    .dword 0x8c83197f8e0c68d2, 0x56cc0838afb08663
    .dword 0xeb73b51781ea62f7, 0x2b9f4e58b8a469e3
    .dword 0x3cb642609513f3e9, 0x10cc45a4e342c077
    .dword 0x4260ac0b07a9f6b0, 0xcfd02fe4f01d76a3
    .dword 0x7817683805060e9c, 0xdd25694b675039c3
    .dword 0x6bd75ea8a57706cc, 0xbd311a2f3f5c3da9
    .dword 0x1c762f021713191c, 0xd1603f5a703990a1
    .dword 0x56f6fb7bbaebd74c, 0x2bd801b2018f7c34
    .dword 0x1cde6585e76b48f7, 0xff9020b60e450d16
    .dword 0x82033ba20b9e22e6, 0xa10e5a52c849f2e7
    .dword 0x66034e55a45f3406, 0x55cb3c5b8923420a
    .dword 0x43b3dc2fbe47ca57, 0xa403d9cada1b793b
    .dword 0x69120c3e8687b247, 0x81dbaca14ead26cb
    .dword 0xb9952d8bda4700dc, 0x1410e0237ef5e5c7
    .dword 0xff398b225a31ca35, 0x336f4a36b40dd505
    .dword 0x672e2ac5544c6c48, 0xee3bae0f854aedc3
    .dword 0x2993629e1776eeee, 0x4273d1587be861a3
    .dword 0x38d9ed64a89b01a8, 0xc704b1f2b531f056
    .dword 0x8bd027d3ce7da0fd, 0x13f1c16c75cf4fc1
    .dword 0x9e4667c849314aed, 0xdabf672bd98314a3
    .dword 0x3f2a0c0ba2a6476c, 0x22b48f0e60fdb3a1
    .dword 0x7c8dd680d2fb6477, 0x3da8dfdcb1683278
    .dword 0xe374c3cea8a1c521, 0x43ac20b8ecfa57b9

    .align 12
data1:
    .dword 0xc4cbc600951894af, 0xc2ab366cd852dbee
    .dword 0x924b286c345823d2, 0x865549d3a72355fd
    .dword 0xc487c141ce4cf944, 0x115ea5eeebf9c6dc
    .dword 0x508cf50f8672fe11, 0x1d621d505e472e2b
    .dword 0x565192216ae05270, 0xf26810aa3ea744de
    .dword 0x7aae8f00d7783ba1, 0x2badea967d7232a6
    .dword 0xb1be73d8cf2fba89, 0xe61a295eeef16776
    .dword 0x745711b1321bf8ac, 0xa5a061cbe1458328
    .dword 0xabf3422dae34f1e5, 0x631b34cec3c334a8
    .dword 0xd7560c46df3780e2, 0x79375e62410e96e5
    .dword 0x412ae505093d2e7f, 0x50a9f91297c1acbc
    .dword 0x92aee9b7e62c21a5, 0xfea6c471d90af993
    .dword 0x8e182dc6696ffa86, 0x663cdb27dc5ac219
    .dword 0xc5d9d12d09238fce, 0xe7144e46d0ee470
    .dword 0x8096e03c4e494377, 0x9dc05a811b5bf9ca
    .dword 0xdf260c0383b4354, 0xbad8ae4b4538e741
    .dword 0xb2351f634ded8a71, 0x94d12b6917b485a7
    .dword 0x6eb028cbb5deea56, 0xad1c8e24eebfa452
    .dword 0x89670d0e206771e7, 0x5d7efd4a8e1e6f8a
    .dword 0x5558d50200055df4, 0x9ff63d9bf9b2fe7d
    .dword 0x1d88c424829a0d0d, 0x45a577c74a41c801
    .dword 0xe1309b5645690db3, 0x616eb9e0ac8f11ec
    .dword 0x7e9c3db8ab13f51f, 0xb44b8d4eae4b130b
    .dword 0x1ff8d0b4ddc43994, 0xa351a76a4682a907
    .dword 0xa22134ca90f43c4f, 0x8b2c3e583a5b4c37
    .dword 0x3dcd8f4e9790026f, 0x5eefe30130218f9f
    .dword 0x41adfd56ade22522, 0xd7ca977340daa840
    .dword 0x312ab1a97b173ab8, 0x644fe3856ccc1c92
    .dword 0x988f4af5cd9e99bd, 0x370e61d8bdd348d4
    .dword 0xdbf402b34ace81d5, 0xd6d7a78953814a56
    .dword 0xe06a8ae0549864c5, 0x6862b352556368e3
    .dword 0xd00abb3b288f445a, 0x48ebb15b9111fde
    .dword 0x3e05784205266941, 0x9aeac6f069cfffa7
    .dword 0x9cf658550c6b6bf9, 0x3cec07f083afd068
    .dword 0xbc5ba803dd6b1918, 0x3d7f6189e79ad92a
    .dword 0x58cd1d979767682d, 0xd1cf4687a02ea893
    .dword 0x27971a47f39d22a7, 0x1c9f192a32939780
    .dword 0x51afa49675a3d7e9, 0xf689265969d70767
    .dword 0x3d4df1373c5b4282, 0x685261804e4ab57d
    .dword 0xc17cc43977bb8121, 0xf08292c803916e3e
    .dword 0xe0756ad91a5c7104, 0x11eebc26f72c8752
    .dword 0x998c5a0789569e5, 0xc09df52a56749e45
    .dword 0xbb81f09b9f169ab7, 0xece464a9dc51b87b
    .dword 0xe1d7d24cf6f7ce9c, 0x4ada50ed4a207e9e
    .dword 0x182257fb1719d742, 0xe4088095bcb90522
    .dword 0xdc78d0a2eab243d0, 0x7072bec545e711ed
    .dword 0xf8dac42d835f6be, 0x780feff66ae1bcc1
    .dword 0x84a9e3113caaa9b9, 0x12b50ff4d61667f9
    .dword 0x88fcfcd1853526c6, 0x2ca8c3744464571b
    .dword 0x487714116151cd04, 0xd804bb2dcee06c5d
    .dword 0xec26665cf232668, 0x947192b34d1110b1
    .dword 0x8a5140ecfa969356, 0x9f6f01680a9ddb7b
    .dword 0xfb21d215961098d2, 0x811772a3095e514f
    .dword 0xc6a5e1396c773f19, 0x85bb3672b3c4abf1
    .dword 0xbc46182100120a27, 0x2a6cecbf396c0a43
    .dword 0xa01edc924a6e96e3, 0x8fa0d75b2a7a024
    .dword 0x972c929ab7623437, 0x28c590a8ee3c139
    .dword 0xbf2bca8b7e1ef60f, 0xc4f9412246bc87e5
    .dword 0xe4995515d0500a11, 0xeacaed13f6e6b3de
    .dword 0x45bb94cd1c1057a9, 0x156c4f687f7376c9
    .dword 0x33f1b7b90e0065a8, 0xbe6ba8af9ac5070d
    .dword 0xf6f03b1acec3d354, 0x4b5cefcc217f4c0d
    .dword 0xa22fa28f32dc6cfa, 0xcd7b4a1318a79300
    .dword 0x97abd1c69b61561e, 0x5de892ddb6389424

    .align 12
data2:
    .dword 0xc05da0cd3d1bd8ce, 0x6df8aef067b888da
    .dword 0xaf57c5fb8e47c29d, 0x51705a014d3c5eed
    .dword 0xeee6de06ccf6cfc5, 0xe4803637faa8af4
    .dword 0x5b0f76b69ecd8ffc, 0x234a6e58eb745407
    .dword 0x5ea6450901b9c02f, 0x934c8499903b57e6
    .dword 0xa8463eb0411ee973, 0x522ef5178a1ef3f1
    .dword 0x9186d7d4ba2d8b87, 0xbec56cf588aa4b43
    .dword 0xe3464ed7d5c849ea, 0x3ce2ffba607bf20b
    .dword 0xee519f90e0a722ef, 0x45c76776285b9cdd
    .dword 0xa89654da2819f268, 0xf6c97e09e8ca5cbf
    .dword 0xddad6a60c059e732, 0x90627338bd1f16c3
    .dword 0x15f384a84fa1cff, 0x7e27a9f367da0514
    .dword 0x713dccf7fa787fd5, 0x5ea00931b04bb645
    .dword 0x7e07c965243432f9, 0xdcc8b44762192279
    .dword 0x5352f82408e6105b, 0xb8dbb8434295a5da
    .dword 0x754bfda5290a88ad, 0xb3dce0169a9408c6
    .dword 0xd7e94f9217f0158d, 0xffa35d004d003c3a
    .dword 0x1ac1e55b22d05f1b, 0xd9f33bd81bf08f7
    .dword 0x483674b2061c8390, 0x7a0799369bd4fb3c
    .dword 0x46c07da4b577ffec, 0x8d3f184cdff8e621
    .dword 0x36531f9f24daf01c, 0x6c96a27d37002672
    .dword 0x5aeaa5f9f4270856, 0x63cf344368d1f2d3
    .dword 0x51f23ce0cd81d0b9, 0xd9e725386b5a55
    .dword 0x532042d5add73b5c, 0x6a4cb6f23dd409f5
    .dword 0x329a4675ecac0f61, 0xa332315805cdb2ec
    .dword 0x7cae7b6d9cb6aeea, 0xc3ed9a915ba66f43
    .dword 0xe17bf600c38ff7dd, 0x244c90e77bea5ce4
    .dword 0x7a9c767f0a4457c0, 0xe5bbd00d34f2fd64
    .dword 0x1fef92f18f7c6410, 0x3de96325748a03e0
    .dword 0xaf20b0d1b4ebf2e7, 0xf465c27d6510647b
    .dword 0x7a7c4b7a92c12921, 0x516f4055de2e7f51
    .dword 0xd1fea6a56c9e9bfb, 0x56bf40dfdbd85c35
    .dword 0xb419eb07cd087cac, 0x10e50d49bfaa9595
    .dword 0xeac5aee3c00ddfbf, 0xee0abaa500e94b75
    .dword 0x3123b8d0fb414b7b, 0xa30ff4c77291f046
    .dword 0x4becdbb854df86c8, 0xffdb58ef4b4879f3
    .dword 0x9d4dc8b8de5fe165, 0x817a5e453c6cd4af
    .dword 0x9d709d2f4bb6bdae, 0x22a57cd57eb9edd3
    .dword 0xc7ed588c4af711c2, 0x975b933a06a0ad02
    .dword 0x9418d0c725d3976a, 0xad41b3791dfbcf72
    .dword 0xa76cd8cd212aba52, 0xa78a03c5d654c75f
    .dword 0x5bd7421850ea0ac1, 0x2b5f44617cfc61dc
    .dword 0xd11e4aa3cf1c5128, 0x9bbb20efe9aaf268
    .dword 0x573d8a6465d6134, 0x7f9fe2d578a078b6
    .dword 0x8de077b16e19f4e9, 0xf2c4556b11d854bd
    .dword 0x75840428cde612f, 0xdf57233f18f44523
    .dword 0xca68f2c3f3a65f9b, 0x5d522d63353a2e2c
    .dword 0xb9ab55ae82f2e412, 0xd5e9955bea84d524
    .dword 0x2a5efe0dc90fd66, 0x3049d3674e82dde9
    .dword 0x367484d9edc53892, 0xcaeef4b62a18ac75
    .dword 0x790486e693c65d9b, 0x7140ef70995ecd36
    .dword 0x5bdd348b6a5a0a40, 0x55027d11ec5e3a48
    .dword 0xfa937228c0126eca, 0xcd9292f333e68935
    .dword 0xd4c53833567912fa, 0x1f6ecc1ebf4e10f9
    .dword 0xbcaecd9c934c51d5, 0x5f184848dbbb0782
    .dword 0x7fd531d5534a71c5, 0x5ce140b08313b5e6
    .dword 0xb021a7411389b98c, 0x2b313b5ef2021f80
    .dword 0x58fde02fa6bc4aaa, 0x4860c7d16f59b2b3
    .dword 0x71c079f061fcfe88, 0x3cbf1bfb95f789a9
    .dword 0x4cfa134917c2e13c, 0xcc9609c37b0e7472
    .dword 0x855a508af6facae3, 0x5148df4be02042e6
    .dword 0x502c0a1136f4aea6, 0x8c74cac50644cbec
    .dword 0x37b76b055fbc3c53, 0x3e05b2123e509533
    .dword 0xd43be9a0e8420eae, 0x33b3b0cbe2b83709

    .align 12
data3:
    .dword 0x681fd6b2b8eab556, 0x6cfbe2b307be31ba
    .dword 0x4fd6a0359fdbf846, 0xf2013e5acda5f65
    .dword 0xaec10ef5b7e15071, 0x1cf077e89c609f27
    .dword 0x12000f5e26964b33, 0xc554a5d7846f4706
    .dword 0xec0a1590e313cf9f, 0x84651264bb213582
    .dword 0xaea9a8fe92ce61cd, 0x10d600778af315ab
    .dword 0xfbfe6573b0691443, 0x51adb9e4b3a23d9e
    .dword 0x1f7fab615b7492e9, 0xb714083654d6a4f8
    .dword 0xefc4b58835f678d5, 0xe8d74f6e84389281
    .dword 0x6cb3c018267f0849, 0xea4a1db1bfc168fd
    .dword 0xc700c3b30f0bb9c6, 0xb401b566f4bab785
    .dword 0x2abea683105bdae3, 0x339429afc823eb69
    .dword 0xb75f095032c308cb, 0x558533abee3a5883
    .dword 0xc30618290854e6d1, 0xf829a3d544b098c9
    .dword 0x183699d27773f5, 0x2dc8b0d5b5b29859
    .dword 0x9203e01d0ef3dee2, 0x433bc13d7a810f34
    .dword 0x4e14148e7bd2dee0, 0x4a2d68164883d972
    .dword 0x4c535e51fdc54601, 0x338c564d1f4fb5fc
    .dword 0x2cb88d106b2a8c77, 0x357230ef8a2305bd
    .dword 0x846eb97b107121d2, 0xba6b14ed83a080bb
    .dword 0xec92ff859fb643f6, 0x2eb0820ff0831646
    .dword 0xf49e869bd3c7c94b, 0x12a79b870da73d93
    .dword 0x4fbf02fe212f46fb, 0xc7b1f20ce33e515a
    .dword 0x8874da4540b24fde, 0xa2b4e3b248a0deff
    .dword 0x2dc2bed3383ff6bf, 0x8390916709f8359a
    .dword 0xf0edbd7aa4147a21, 0x50849096b25cae47
    .dword 0x4b54ee2bb65a8eb8, 0x4be0d17d29bcbf67
    .dword 0xa5b4b9d066ebf404, 0x53284ff0a8929dd
    .dword 0xd75ec82092bf287a, 0x8f4032c98400d4aa
    .dword 0x7a3874bbf0a13cb6, 0xf4aa3803a91ff655
    .dword 0xd7f1d132a028527e, 0xe59107ebbfbf4a6c
    .dword 0xec93d0ab1a178afa, 0x4f8a99e1070fb1ad
    .dword 0xdd2e1de8a80048f3, 0x8d230671b938779b
    .dword 0x7efb79c1a47b8555, 0x11c6f635653cb845
    .dword 0x6313b7281eb6b79a, 0x7614c208be055a90
    .dword 0xb0f388fb6b424237, 0xbb4adb458f9fb756
    .dword 0xba6c040e4f66d7a1, 0xe2ce5e0e85ae42bd
    .dword 0xe6ecda8266b698e7, 0xb02f252e2f46f844
    .dword 0xeedbc2dc1195c0ac, 0xf627e3f1d13f6ea9
    .dword 0x7d47f7d0a783826c, 0x7ad53d62deb09071
    .dword 0x3ccbab7da44b6527, 0xca70b8f2f279a427
    .dword 0x34363f42f0924243, 0x47a4dfaac23bcdc
    .dword 0xda8b6cceb5bcb2c3, 0x89355e63d013ae77
    .dword 0xe47c7b508b7a080c, 0xe93bb9fff0edf7c9
    .dword 0xd128be9f0d0dd775, 0x5a57a2f04993110c
    .dword 0xd5bbbcac897d2dd4, 0x52c6424354554cd9
    .dword 0xd016b4f0185a377d, 0xc3845d5278426fdf
    .dword 0x21a7bbb7eca684a6, 0x461fde5b81c4a282
    .dword 0x377ac18380ea12b5, 0x573b946089ebecf3
    .dword 0xff8c8b2b5105218e, 0x60dc23f6ab890942
    .dword 0x6bbe5417332811dc, 0x47e7de44bb9715c2
    .dword 0x96e54f0a5aed8c9e, 0xaa7ba1b3a603bf77
    .dword 0xc60828ccff0b39b1, 0xc2d52fabc78ce54b
    .dword 0xa0743b468c8db55c, 0x8b2d199107cc118b
    .dword 0x55de0720af4ebada, 0x1c2fd7ec9edfd9e
    .dword 0x18fbab6db4db89b2, 0xb2000ff02968106b
    .dword 0xb32f788f0762424d, 0x16ccc6d5d7035289
    .dword 0x1eea593e3c11e951, 0x8b176182d820b71a
    .dword 0x91de74d123bb457, 0x75a82aad9647223e
    .dword 0x40d1b843086ca2a7, 0xbe5dba0234d57065
    .dword 0xde18228dbf82deff, 0x9acfe7bb57426237
    .dword 0x72395a78b722f354, 0xdcd97ea0ad48295d
    .dword 0x61dda6dd7601b07, 0xa0a958783fdf63cf
    .dword 0xdefa470a7de5b377, 0xc5791157fe4e87a7

    .align 12
data4:
    .dword 0xde6abb69b374bc14, 0x46605ed4abefb296
    .dword 0xe4ef980182e457c3, 0x2485228e626cd02f
    .dword 0x844c1bfe669d0cdc, 0x55da660c238fdc9
    .dword 0x6302ffb4f19a6fc1, 0x8a78149e9100151
    .dword 0x15b8df6da04a1314, 0x9c00218d6120920f
    .dword 0x537691157e36c5e2, 0xa2c141bf38c1cbd3
    .dword 0x4aaf3188ac5f5c68, 0x8dfd62e8db28e7a5
    .dword 0xa14af257f5007301, 0x245490cf1fb254b7
    .dword 0xc28760437b0f26e8, 0xb5dfd8aa19156289
    .dword 0x72d2d10eec35b47, 0xa537652887eee9ca
    .dword 0xd08c4baa1b2ccc4, 0x64cc2769a9781638
    .dword 0xe1260db631a71a15, 0xfeb0bd735cfa14c4
    .dword 0xeb85d62b6f66ac64, 0x1f1de2e8906f447e
    .dword 0x31c9a69bc157ac00, 0x901411f52533b93c
    .dword 0xadde3c0e6b44854b, 0x167eb7ede6e6dbd4
    .dword 0x60f27a5a0701c18a, 0x9548664299dd36b7
    .dword 0xcb9ccc743dbdb389, 0x8e86ea1c70912ea7
    .dword 0x2f6076bd32f0f49b, 0xe93bcf201f6f8699
    .dword 0xb5dffcad6a47e0ab, 0x53af09c8c36f6e5f
    .dword 0x8b690877a114cc30, 0x276ad46339860268
    .dword 0xdab4dc96d9e918b4, 0xd3cfda3ee074ec18
    .dword 0x3a324fdcd98a5690, 0x60a3593f8c6d971e
    .dword 0xd44c889097dd7b86, 0x5be8f4683ade4364
    .dword 0x7f7693528e9a628f, 0xa69cbbb20c21aab0
    .dword 0xb806a89accecb028, 0xa487e38b922e5d94
    .dword 0x2aede37d616096b7, 0xa97d721761b07968
    .dword 0x274c113eae71d688, 0xa4d32aa35231374b
    .dword 0xbcb1fbb299b9c66e, 0x2732754808f475c7
    .dword 0x4826f53a2e652515, 0x7d5df32a9d615fcc
    .dword 0xb6facf2dc65349e9, 0xa52b84bfe88bded3
    .dword 0x925f5dc7b921398b, 0xdc7b1f264c2504fe
    .dword 0xf5f0cc6381089eef, 0xe3234960d8b71cff
    .dword 0xbd0b60aeb13acf51, 0xf7588173b9695da5
    .dword 0x57469722e27e8b3d, 0xc42b3a8847888881
    .dword 0x74165fd917e1c22f, 0xdbadbed9fd32f397
    .dword 0xf8f59c3a951acea1, 0x2e7ed57d5ef9f8bf
    .dword 0x2f210252a6f50681, 0x8a7f494afb640dc9
    .dword 0x55583f100ceac163, 0x55158fdf4104d80f
    .dword 0xb9c8e3344afc8b71, 0xafff8195f94c49d6
    .dword 0x15af5b490b66a82, 0xd3f7b8af0c710b03
    .dword 0x8cb0cab47550cda8, 0xf8237a0401c64eab
    .dword 0xeed14b21381a6401, 0x47211eb482467166
    .dword 0x29490e852ced4e54, 0x8da1de9d44e48b75
    .dword 0x20c9933009df74f5, 0x38705d3d6a59b16b
    .dword 0x9aba430819d6a3e, 0xd9a309a667dd9772
    .dword 0x349867bcb3cc7bc6, 0xf43933ad74f20c8f
    .dword 0x283ba0501f73923c, 0x483467460d857160
    .dword 0x68959dceac4c877f, 0xa2c9e84d15ce40b4
    .dword 0xc5bada04298c3dbd, 0xd8dfe5689567afec
    .dword 0x7dd3824d8c80ea8f, 0x5e938d291d7ad2d0
    .dword 0xb247ad3dc1d21ddc, 0xb522ea6746f8e812
    .dword 0x69952a5c577c5e6b, 0x47c9fe21432f47a4
    .dword 0xc72ae93a57a0d9db, 0xd80d7ebe079de523
    .dword 0xb3fbd743e8d703f1, 0xaece20a64b137130
    .dword 0xf0f99af5ba4ca274, 0x90ec128b970cee6c
    .dword 0x6ba8b770f3f56979, 0xecf7e6b4ea253969
    .dword 0xde4cc9e8d48d187, 0x298f5bc1a2666909
    .dword 0x6fbba82c3c3ecc20, 0x90316e7b45770015
    .dword 0xbcbad9f651efbd23, 0xa44c3db34be86c09
    .dword 0xcca2142e58e0d0d3, 0xc18d04a42e3f7a69
    .dword 0xe6de0eeafc301071, 0x3981edddf15b3644
    .dword 0x87a79c525063596a, 0xfaf1cd79eeb8bf09
    .dword 0x3e775c3e7815f163, 0x8c3ddaff1033c4a1
    .dword 0x1f35bcf8030a5736, 0xbbcf0206a7daa3ff

    .align 12
data5:
    .dword 0x2c1c111ad197174b, 0x8806cca2c08d3bd1
    .dword 0xe2df3e56b77048cb, 0xbb2e8104d849c6e
    .dword 0x12f7f377aab858a0, 0xcf22b39a455d32af
    .dword 0x4f38021b44cc1f58, 0x1656027a48e0481f
    .dword 0x9136f60edeeec5bf, 0x8787d2558a19d24e
    .dword 0x6a7177a7ed1956b8, 0xf72cd1080eb70e96
    .dword 0xbd574f5361853c6c, 0x501e5e52aaafe9fb
    .dword 0x6388ffb903f4766c, 0xba96698bd926190
    .dword 0x45f6d0ef21ed2713, 0x8c0d702c0e184717
    .dword 0x503c2055e6e8ec6d, 0x80e08ded1f2f4d37
    .dword 0x4c381b695e694126, 0xfa56942aa84b3d1a
    .dword 0x66c7a4ed0149f350, 0xd8f13cee42007793
    .dword 0x76474ee5ae5560c4, 0xdb534cc0d5f19776
    .dword 0xc6d4480169dff028, 0x61850b9055187613
    .dword 0x5e11d4ac25354a50, 0xee48346b2b39a62c
    .dword 0x19ce898e72985247, 0x1c77121841b762e4
    .dword 0x64165e9ef6ebb2b5, 0xbddf06660f85a7a7
    .dword 0xbac74cb6df2a9f47, 0xe164516457d81456
    .dword 0x6551daaf8da7a21c, 0x67bdf93fd40fd3b1
    .dword 0x9ff78b1f8ad87f60, 0x79b048746e078e91
    .dword 0x17ed0714d3f07d03, 0x42b929e991a6cd4f
    .dword 0x3baf36589d45fa16, 0xdd41131db4f82f4c
    .dword 0x4d33c1f777c99, 0x2a17a78c1fb32d65
    .dword 0xd9fdcf75289f3048, 0x638deb31db54c57f
    .dword 0x713bebc90b4cb3ae, 0x2bdbc95fa01009db
    .dword 0x429eda1496bc1621, 0x3a1a56bea8bc7601
    .dword 0x9699d95f35604027, 0x990d90f34dbe7258
    .dword 0xac98a74e11508e2b, 0x6be10fd125cb1b55
    .dword 0x146a8b4dee943306, 0x5021819e0e7efdd9
    .dword 0xe3bc3536a2ec3837, 0xee265fbdc1c1a4d9
    .dword 0x4422fbcc3660d5c7, 0x93f19dd117161432
    .dword 0x92a7ba588b4adac7, 0xb564e41fc8e637e3
    .dword 0xcaca58806dd8ce5c, 0xc97820a05fdd0476
    .dword 0xf939f79db62b107a, 0x159ecb77b881d7a3
    .dword 0x9561ca907c3fdc42, 0x9f10f7a3f42b461d
    .dword 0xfb80ac42ba3c8773, 0xf79882c8993c5d70
    .dword 0x481f558045bccc26, 0xc7d7ccf65e24dcb2
    .dword 0x70ff74c72d537ac2, 0x628daad1325f4d74
    .dword 0xcc40f962020f79a9, 0xf9b7f59854b23af3
    .dword 0x2a72651b5ca03456, 0xdb1ace31b459fce7
    .dword 0x52cbd5b8a7154cbb, 0x9276e39b37deaa88
    .dword 0x66acad0d291591df, 0x596a01a8f59a0091
    .dword 0x919cfc2d38239adb, 0x375caeaf59557f84
    .dword 0x4f616ded4ecb5f0b, 0x7cb0b4e8b069f714
    .dword 0x1393e20ac1f7456, 0xa5b86abc3b754872
    .dword 0xe4f9964abb1930d0, 0x1259fe4b26130314
    .dword 0xca5c83e235b257c8, 0x5822cee78211f256
    .dword 0x6ef0d92965525b5b, 0x6749098ffd95c724
    .dword 0x5fcdfea19bdcda99, 0x7582e9006608c7e9
    .dword 0x5e87b54f89f90b8, 0x1e62376701938c75
    .dword 0x1c48ef4347ad9c9e, 0xcf3ebe8663936763
    .dword 0x1bbfbbf0aa2d7f9d, 0x3c00765e8d9277da
    .dword 0x63c1265b5fd35588, 0xc8c5a6e4556d807e
    .dword 0x46a652f87d36a76b, 0x9d6acde0ab01d051
    .dword 0x4165cf19c8850c91, 0x2ce266d51cde96f6
    .dword 0xab047e453eded56b, 0x9ff289419e4b82e6
    .dword 0x397aaee5e510315a, 0xa76e14b4256a1a74
    .dword 0x89827556ba9620ec, 0xf8fef39f9c4ef8dc
    .dword 0x57e244745a2ac446, 0xc87c7b3bff0f5558
    .dword 0xc8cb5e15b3bb4ca8, 0x1964092077140caa
    .dword 0xc6e1d59e1200e54d, 0xcc64411be396ceeb
    .dword 0x6593b441a6a1ec32, 0x2a4e62b187fce4bc
    .dword 0xc153b9699ca6f531, 0x17096330ccfe8934
    .dword 0x3b260db4e6daf65f, 0xe39abb24517abd23

    .align 12
data6:
    .dword 0xbfd15f3e359025b2, 0x96e23a1f96f83f2b
    .dword 0x83a2214180e2044b, 0x131ff643292e439f
    .dword 0x75c887b66fe979a0, 0x32618eb7a2086a9f
    .dword 0x61210446ccf269e1, 0x1fdba7bc8e9c6cf8
    .dword 0xed0f80b858123618, 0x88498ab3290254d0
    .dword 0xa443139a07212b9c, 0x7430ab6292eaca64
    .dword 0x5598e38742934259, 0x9e04dccc428c05dd
    .dword 0xd039718649c09977, 0x18fb86eac37bacb6
    .dword 0x357b85916062bf5c, 0xaf5b75692a9171b8
    .dword 0xe771b9d7e1dd13a8, 0xd9bc9b5f81c7217c
    .dword 0xa60a575058ef229e, 0xc65b9725450822eb
    .dword 0x416053c5285bf8fc, 0x5ce082fab3a4c759
    .dword 0x7c13c62c547d04de, 0xa50c01eb34040873
    .dword 0xe42de353e2be89c2, 0xd5218665a079023c
    .dword 0x1ffb7f06b198c76f, 0xdffc1be9b4a439d6
    .dword 0xaad9d5145c5522f8, 0xe0c34abbe40daaa4
    .dword 0x74fc493f889f83f4, 0x4260d19795508687
    .dword 0xd7035d809b28dd7d, 0x78e1aff9617863f5
    .dword 0x92c7ec24626d8052, 0xe5141e40aa03cacf
    .dword 0x5083d1583e82ce61, 0x168fd6ebbfae542a
    .dword 0xb30f9c6b6150b356, 0xfa15195249821c15
    .dword 0xf6895c9adbc8b5a1, 0xbf5858427216aee0
    .dword 0xbd376f03c62b21d, 0xdd8aaf35f8e64c62
    .dword 0x77f03b566dfa5a6e, 0xf30103084846b1a9
    .dword 0xeecf9cad70940dba, 0xbee90b7f13a8fdfc
    .dword 0x12ff5da866820cad, 0x38fe24ae09bddf8e
    .dword 0x61c3fbb4e0cf064c, 0xb1f31b213c605844
    .dword 0x9773607d75cd25d9, 0xa5612bf2ae150806
    .dword 0x122d208eacd5270a, 0x3de62d81839361e7
    .dword 0x81ac5b9d8f793a1c, 0xd06dffdc5d78562
    .dword 0x8f4a011ab9afac86, 0x1d2abf92e5894280
    .dword 0x18b8ca4099735ec0, 0xc3e376a131a9f867
    .dword 0x9a77da2ae4bc1e3, 0x9c0a66b00ff54eca
    .dword 0x3172808b2f679b0f, 0xab0b1a70fc2601ed
    .dword 0x5e5c4c50af0e162, 0xb9b00b6ed47a0c89
    .dword 0x496b851d3f4f5969, 0x1f7acd061270764c
    .dword 0xc4b47cfc11816f28, 0x3f7922dbd72252c
    .dword 0xb491abac121841ef, 0x3a0ba04fb95dab50
    .dword 0x382b6845a2e3b29a, 0x2fa428d76dfb3bc0
    .dword 0x168cdd792bbdc683, 0x506f0c782d67e023
    .dword 0x2cdab5a9650a506d, 0x9f7aa7b811634108
    .dword 0xc0c6a37c12eaac66, 0xbc10566535d8c542
    .dword 0x4f654795708e6097, 0x2f32c801b947913b
    .dword 0x3339e2eeaac82a96, 0x783d2a2d188c2409
    .dword 0x95012b65e2c24577, 0x516abcde33ad6153
    .dword 0xc80912e6f5a7b06b, 0xaccec8fa50dd96e7
    .dword 0x147a2192d9581e20, 0x35712f489e7c7f2f
    .dword 0x4ec9c66c054df1ac, 0x6c338cfa64c91a2f
    .dword 0xa42972f1cb4097bc, 0x6eaf1e231d68333c
    .dword 0x568524d1888fccc8, 0xa984931fd59a08df
    .dword 0xda247bb6a9541c79, 0x13cb3f8f93b3ba05
    .dword 0x922c56c2277426ce, 0x46f0d186cb23852d
    .dword 0xbb9e1b1b65a024f2, 0x20c1de20e905ade6
    .dword 0xbc62e5f3258da083, 0xd12ac99e424e87b0
    .dword 0xf518e869e2f81de3, 0xe6e5de3b14b9aec4
    .dword 0x9d5032922fa3c7fd, 0x25ec38a375d6c708
    .dword 0x8b6ca3abfe98341f, 0x4f3aa0a45e072332
    .dword 0x6f38d51290cbcfa, 0x1a07bf4396ab40f3
    .dword 0xfbbe95b0c333d701, 0xbd31adfadf9a42ea
    .dword 0x958b9d21be0b2b8e, 0xc119d15f1fd7488b
    .dword 0x1979637838116bfc, 0x33c3513d7b052569
    .dword 0xd2ae96b754e2539e, 0x41b1eaf15d170b73
    .dword 0x1df3e12332e165e5, 0xe8c30c075462b040
    .dword 0x255d1dddc756327b, 0x7ee1ead9deb57f34

    .align 12
data7:
    .dword 0x687322846a9b4616, 0x46773114d715fc72
    .dword 0x897659d8ee4f66fe, 0x881b447d5529210e
    .dword 0xb97f0c7511cfe81b, 0x7b1c107fa372f741
    .dword 0xa8cb168e907556c, 0x661da1983b27b042
    .dword 0x2bce0d6d5d3067a9, 0x6e661d4e273a0ee4
    .dword 0x56f7bafa68b18f33, 0xf0145a27e54b8f8f
    .dword 0x3d3ffd4d3be18b4e, 0x3844967af6cfa145
    .dword 0x7b5e9dda10c7bcbf, 0xdafb80c47d768fce
    .dword 0xfaceaa9b4e1f54fe, 0xa18fdd0fba24de4c
    .dword 0x67be60fc3b7f1ddb, 0xf5ffdf3c22c11e9e
    .dword 0xaa7d84e1b4a05665, 0xf82652719838c31b
    .dword 0xd9369f40022be61a, 0xe32e4879ad4530aa
    .dword 0xe2b82c45be27dfa5, 0x76e732ee367d6fe2
    .dword 0xf9706b7f3dc5e0d8, 0x8418f6c229e099c6
    .dword 0x4ec4ce8bec26e36d, 0xf10ec92eacb4214
    .dword 0x28462115c3663b10, 0xc5df4dc783b4ebce
    .dword 0xdfa5fa3d08727450, 0x8eb90c97e4596ec2
    .dword 0x9c296cbcc71cf8af, 0x2048be2d377d558
    .dword 0xb24c9097d0596b89, 0x3ba4086e64963645
    .dword 0xe45c98dbd41f60db, 0xc9f337593ae060a9
    .dword 0xf91fce9dd334fb27, 0x37020cc9a65d9f2
    .dword 0xe9e9228c2e097a03, 0x83833d160145044c
    .dword 0xac28915667a27edc, 0x7fa7b73b564c1db5
    .dword 0x907e37d676ef1f, 0x38869154cfb10fd6
    .dword 0x48219099d730006a, 0xb80db7a86232e23f
    .dword 0x471f7b638e73c9ed, 0x7d6b9889e95dbf0b
    .dword 0x782ea47267308086, 0x7b7f044c491a5a34
    .dword 0x70c81e738c26c264, 0x8f9660de090fcd86
    .dword 0x3e77512c44c9ce20, 0x2fe955a94c737082
    .dword 0xa82b07fce0d34eec, 0xb563a6494b61dc8d
    .dword 0x703abf72e01c94c9, 0xc7c4ce0b7aa8115
    .dword 0x3368c74c84cc5a9f, 0xa6bb450b6e9db7b0
    .dword 0xa5f7f0fcfbdc2c55, 0x182429361db086ee
    .dword 0xe8fe87c5ad6baa4b, 0x5a4a1c14a0a0bd46
    .dword 0x85e988c97296d379, 0xa4511786c753ecf4
    .dword 0x4f764c1889bf1dbf, 0x68c88e173cb0620
    .dword 0xef62114ff619e93e, 0xc77a82b2a6529f2
    .dword 0xa89e5e2f3f0ab0bc, 0x941966bb4b0df389
    .dword 0x17e208ef6a9c12b0, 0x93a979364a9f989c
    .dword 0x562ca79670c98544, 0xb4ccc268eb9ea2e
    .dword 0xc40f4f3d029dc9b2, 0x5bfa81429535921f
    .dword 0x8ae96d42182e72f4, 0x7ddcccb56c517dff
    .dword 0x59b89738c4e7bb47, 0xe4ed841d1f792872
    .dword 0xca7e89578d1c492b, 0x9405646f092dfbae
    .dword 0x449c8053afc6402d, 0xb0cf183858ffd725
    .dword 0x19ef44a59d214e24, 0x6a0ba5a1440a7faf
    .dword 0xcd60ca9598c48d3e, 0x4c250fe2661b98e3
    .dword 0xb07f9026daee58c0, 0xd7e31aafe85093a2
    .dword 0x3281f5b28135d1aa, 0xe1c0fb406b11bf8f
    .dword 0x9b4c2e4a4dbecd51, 0x522636e4c193a373
    .dword 0x698d7d70ad51f4b2, 0xa94b42fdea0562ec
    .dword 0x2dddc4013cddfed9, 0xd0743c4b4774bc12
    .dword 0xc159d72ceaeeea44, 0x2e51d38233a8df31
    .dword 0xcb71378bd1ddcf4, 0x95cbf954b6e95c5e
    .dword 0x34be857ba01f7a0, 0xb7a45b3c1da43dcb
    .dword 0x1f9b4d657b92b2a7, 0xb3110795e809f2d5
    .dword 0xc2646dc57f7a994d, 0xdffe21146dceaba
    .dword 0x8af95ee84b10e052, 0xadb9b1099810ca97
    .dword 0x24a790a94ef3b639, 0xab898ec9d13f5766
    .dword 0xfc8eaa0ec51f9849, 0x68f49ea53b52260d
    .dword 0x2a2ae019d2d8c388, 0x77b08c42cb59de92
    .dword 0x508471ca4a6a629a, 0x687c190f933046e5
    .dword 0x221f2f0bb3a4a264, 0xcb374c3ece2c96eb
    .dword 0x5ef11f64acd2ccf3, 0x855bda58bd88411b


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
