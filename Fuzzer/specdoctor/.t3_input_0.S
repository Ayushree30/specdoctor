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
                    la x19, data7                             
                    add x22, x22, x19                         
                    fld f0, 16(x22)                           
pfx.bb0.l1:         andi x20, x20, 0x3f8                      
                    la x21, data7                             
                    add x20, x20, x21                         
                    fld f1, 16(x20)                           
pfx.bb0.l2:         andi x19, x19, 0x3f8                      
                    la x22, data0                             
                    add x19, x19, x22                         
                    fld f2, 0(x19)                            
pfx.bb0.l3:         andi x21, x21, 0x3f8                      
                    la x19, data4                             
                    add x21, x21, x19                         
                    fld f3, 16(x21)                           
pfx.bb0.l4:         andi x22, x22, 0x3f8                      
                    la x20, data7                             
                    add x22, x22, x20                         
                    fld f4, 8(x22)                            
pfx.bb0.l5:         andi x20, x20, 0x3f8                      
                    la x22, data7                             
                    add x20, x20, x22                         
                    fld f5, 24(x20)                           
pfx.bb0.l6:         andi x22, x22, 0x3f8                      
                    la x21, data0                             
                    add x22, x22, x21                         
                    fld f6, 16(x22)                           
pfx.bb0.l7:         andi x18, x18, 0x3f8                      
                    la x22, data3                             
                    add x18, x18, x22                         
                    fld f7, 0(x18)                            
pfx.bb0.l8:         andi x22, x22, 0x3f8                      
                    la x20, data6                             
                    add x22, x22, x20                         
                    fld f8, 16(x22)                           
pfx.bb0.l9:         andi x22, x22, 0x3f8                      
                    la x18, data5                             
                    add x22, x22, x18                         
                    fld f9, 8(x22)                            
pfx.bb0.l10:        addi x18, zero, 241                       
pfx.bb0.l11:        addi x19, zero, 721                       
pfx.bb0.l12:        addi x20, zero, 1986                      
pfx.bb0.l13:        addi x21, zero, 1642                      
pfx.bb0.l14:        addi x22, zero, 296                       
pfx.bb0.l15:        addi x23, zero, 27                        
pfx.bb0.l16:        addi x24, zero, 1247                      
pfx.bb0.l17:        addi x25, zero, 1949                      
pfx.bb0.l18:        addi x26, zero, 1484                      
pfx.bb0.l19:        addi x27, zero, 1971                      
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
prp0.entry.l0:      fnmadd.d f0, f3, f4, f1, rne              
prp0.entry.l1:      ori x21, x20, 471                         
prp0.entry.l2:      call fn2                                  
prp0.entry.l3:      fence.i                                   
prp0.entry.l4:      fcvt.wu.s x22, f4                         
prp0.entry.l5:      slli x21, x22, 12                         
prp0.entry.l6:      fsqrt.s f2, f4, rmm                       
prp0.entry.l7:      fmax.d f0, f1, f4                         
prp0.entry.l8:      rem x19, x22, x18                         
prp0.entry.l9:      jal x18, prp0.bb0                         
prp0.bb0:
prp0.bb0.l0:        fclass.d x22, f2                          
prp0.bb0.l1:        fmul.d f0, f1, f2, rup                    
prp0.bb0.l2:        slti x21, x18, 1856                       
prp0.bb0.l3:        slliw x21, x20, 7                         
prp0.bb0.l4:        fmadd.d f1, f4, f0, f3, rdn               
prp0.bb0.l5:        rem x21, x18, x22                         
prp0.bb0.l6:        fcvt.d.w f0, x20                          
prp0.bb0.l7:        fcvt.wu.s x21, f4                         
prp0.bb0.l8:        bltu x20, x21, prp0.exit                  
prp0.bb1:
prp0.bb1.l0:        sltu x19, x22, x18                        
prp0.bb1.l1:        fnmsub.s f1, f4, f2, f3, rne              
prp0.bb1.l2:        fdiv.d f1, f0, f3, rup                    
prp0.bb1.l3:        fsgnjx.s f2, f1, f0                       
prp0.bb1.l4:        xor x20, x22, x21                         
prp0.bb1.l5:        fmv.w.x f2, x22                           
prp0.bb1.l6:        call fn0                                  
prp0.bb1.l7:        fmin.s f0, f4, f3                         
prp0.bb1.l8:        fsgnjn.d f1, f2, f4                       
prp0.bb1.l9:        fadd.s f3, f1, f0, rdn                    
prp0.bb1.l10:       bge x19, x18, prp0.exit                   
prp0.bb2:
prp0.bb2.l0:        fcvt.d.w f0, x21                          
prp0.bb2.l1:        remu x22, x18, x19                        
prp0.bb2.l2:        srl x21, x22, x19                         
prp0.bb2.l3:        fsgnjn.d f2, f0, f3                       
prp0.bb2.l4:        remu x19, x21, x20                        
prp0.bb2.l5:        fmv.d.x f1, x21                           
prp0.bb2.l6:        bne x22, x18, prp0.exit                   
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      fle.s x22, f3, f4                         
prp1.entry.l1:      fle.d x21, f4, f0                         
prp1.entry.l2:      fnmadd.d f1, f2, f3, f4, rup              
prp1.entry.l3:      call fn4                                  
prp1.entry.l4:      fcvt.s.l f3, x21                          
prp1.entry.l5:      fsgnj.s f4, f2, f3                        
prp1.entry.l6:      addi x21, x18, 83                         
prp1.entry.l7:      bge x22, x21, prp1.bb0                    
prp1.bb0:
prp1.bb0.l0:        rem x21, x22, x19                         
prp1.bb0.l1:        remuw x20, x19, x18                       
prp1.bb0.l2:        sll x18, x19, x21                         
prp1.bb0.l3:        fence                                     
prp1.bb0.l4:        srl x20, x19, x18                         
prp1.bb0.l5:        fnmsub.d f1, f2, f4, f0, dyn              
prp1.bb0.l6:        call fn2                                  
prp1.bb0.l7:        blt x22, x20, prp1.bb3                    
prp1.bb1:
prp1.bb1.l0:        fence                                     
prp1.bb1.l1:        bgeu x21, x18, prp1.bb3                   
prp1.bb1.l2:        sltiu x22, x20, 1344                      
prp1.bb1.l3:        bne x20, x22, prp1.bb2                    
prp1.bb1.l4:        call fn2                                  
prp1.bb1.l5:        call fn2                                  
prp1.bb1.l6:        slti x20, x19, 353                        
prp1.bb1.l7:        and x18, x22, x20                         
prp1.bb1.l8:        beq x20, x21, prp1.bb2                    
prp1.bb2:
prp1.bb2.l0:        call fn4                                  
prp1.bb2.l1:        fmsub.s f1, f0, f3, f4, rne               
prp1.bb2.l2:        call fn0                                  
prp1.bb2.l3:        fmax.d f1, f0, f4                         
prp1.bb2.l4:        fnmsub.d f1, f2, f3, f0, rup              
prp1.bb2.l5:        fcvt.d.s f4, f4                           
prp1.bb2.l6:        bgeu x21, x20, prp1.exit                  
prp1.bb2.l7:        fcvt.d.lu f0, x22                         
prp1.bb2.l8:        jal x18, prp1.bb3                         
prp1.bb3:
prp1.bb3.l0:        addiw x19, x18, 1221                      
prp1.bb3.l1:        fadd.s f3, f2, f0, rdn                    
prp1.bb3.l2:        call fn1                                  
prp1.bb3.l3:        bge x18, x21, prp1.bb4                    
prp1.bb3.l4:        xori x21, x22, 1139                       
prp1.bb3.l5:        slti x21, x22, 152                        
prp1.bb3.l6:        fdiv.d f0, f2, f4, rup                    
prp1.bb3.l7:        sltiu x20, x18, 1474                      
prp1.bb3.l8:        fsgnjx.s f4, f3, f1                       
prp1.bb3.l9:        fsgnj.s f2, f1, f3                        
prp1.bb3.l10:       bltu x19, x20, prp1.bb4                   
prp1.bb4:
prp1.bb4.l0:        div x19, x20, x18                         
prp1.bb4.l1:        call fn1                                  
prp1.bb4.l2:        blt x22, x21, prp1.exit                   
prp1.bb4.l3:        divuw x20, x22, x21                       
prp1.bb4.l4:        fmv.d.x f4, x18                           
prp1.bb4.l5:        fcvt.d.w f2, x19                          
prp1.bb4.l6:        call fn3                                  
prp1.bb4.l7:        fadd.s f1, f0, f4, rmm                    
prp1.bb4.l8:        jal x21, prp1.exit                        
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        mulhsu x20, x22, x21                      
tc.entry.l1:        fmin.s f0, f2, f4                         
tc.entry.l2:        bltu x19, x20, tc.bb0                     
                    spdoc_check_c
tc.entry.l3:        xor x18, x19, x22                         
tc.entry.l4:        andi x22, x22, 0x3f8                      
                    la x21, data5                             
                    add x22, x22, x21                         
                    amomin.w x18, x20, (x22)                  
tc.entry.l5:        blt x22, x21, tc.bb1                      
tc.bb0:
transient:
tsx:
tsx.entry:
tsx.entry.l0:       fmin.s f8, f6, f7                         
tsx.entry.l1:       andi x25, x25, 0x3f8                      
                    la x27, data1                             
                    add x25, x25, x27                         
                    amoadd.d x24, x26, (x25)                  
tsx.entry.l2:       fdiv.d f9, f8, f7, rmm                    
tsx.entry.l3:       ori x23, x26, 544                         
tsx.entry.l4:       call fn1                                  
tsx.entry.l5:       andi x23, x23, 0x3f8                      
                    la x24, data4                             
                    add x23, x23, x24                         
                    amoadd.d x27, x26, (x23)                  
tsx.entry.l6:       fsgnj.s f6, f8, f5                        
tsx.entry.l7:       bgeu x23, x26, tsx.bb2                    
tsx.bb0:
tsx.bb0.l0:         slliw x23, x25, 4                         
tsx.bb0.l1:         fsgnjx.d f6, f5, f8                       
tsx.bb0.l2:         srliw x25, x27, 15                        
tsx.bb0.l3:         call fn3                                  
tsx.bb0.l4:         flt.s x27, f5, f7                         
tsx.bb0.l5:         fsqrt.s f6, f9, dyn                       
tsx.bb0.l6:         jal x24, tsx.bb2                          
tsx.bb1:
tsx.bb1.l0:         andi x27, x27, 0x3f8                      
                    la x25, data0                             
                    add x27, x27, x25                         
                    amoor.d x24, x23, (x27)                   
tsx.bb1.l1:         fnmadd.s f9, f5, f6, f7, rtz              
tsx.bb1.l2:         fnmsub.d f6, f8, f7, f5, dyn              
tsx.bb1.l3:         andi x26, x26, 0x3f8                      
                    la x25, data3                             
                    add x26, x26, x25                         
                    lr.d x24, (x26)                           
tsx.bb1.l4:         call fn3                                  
tsx.bb1.l5:         call fn2                                  
tsx.bb1.l6:         andi x24, x24, 0x3f8                      
                    la x23, data1                             
                    add x24, x24, x23                         
                    sc.w x26, x27, (x24)                      
tsx.bb1.l7:         fsgnjx.d f6, f7, f5                       
tsx.bb1.l8:         bltu x23, x27, tsx.bb2                    
tsx.bb2:
tsx.bb2.l0:         andi x25, x25, 0x3f8                      
                    la x23, data4                             
                    add x25, x25, x23                         
                    lh x24, 18(x25)                           
tsx.bb2.l1:         andi x25, x25, 0x3f8                      
                    la x26, data7                             
                    add x25, x25, x26                         
                    amomaxu.d x23, x27, (x25)                 
tsx.bb2.l2:         lui x27, 3539                             
tsx.bb2.l3:         sraiw x24, x23, 26                        
tsx.bb2.l4:         fcvt.lu.s x26, f7                         
tsx.bb2.l5:         call fn4                                  
tsx.bb2.l6:         andi x25, x25, 0x3f8                      
                    la x27, data0                             
                    add x25, x25, x27                         
                    amoand.d x26, x24, (x25)                  
tsx.bb2.l7:         la x23, tsx.bb3                           
                    jalr x24, 0(x23)                          
.align 8
tsx.bb3:
tsx.bb3.l0:         fsgnjn.s f5, f9, f7                       
tsx.bb3.l1:         sub x25, x27, x23                         
tsx.bb3.l2:         and x27, x23, x25                         
tsx.bb3.l3:         fcvt.d.lu f8, x25                         
tsx.bb3.l4:         div x23, x26, x25                         
tsx.bb3.l5:         remuw x25, x24, x27                       
tsx.bb3.l6:         fcvt.d.wu f5, x24                         
tsx.bb3.l7:         fdiv.s f6, f9, f5, rdn                    
tsx.bb3.l8:         slliw x23, x27, 19                        
tsx.bb3.l9:         fsub.d f8, f6, f9, rup                    
tsx.bb3.l10:        bgeu x27, x25, tsx.exit                   
tsx.exit:
transient_end:
tc.bb0.l0:          remw x22, x19, x20                        
tc.bb0.l1:          srl x19, x20, x22                         
tc.bb0.l2:          call fn1                                  
tc.bb0.l3:          flt.d x21, f3, f1                         
tc.bb0.l4:          call fn2                                  
tc.bb0.l5:          fcvt.lu.s x21, f1                         
tc.bb0.l6:          bltu x20, x22, tc.bb1                     
tc.bb0.l7:          fnmsub.d f0, f3, f1, f4, rmm              
tc.bb0.l8:          bge x19, x22, tc.exit                     
tc.bb1:
tc.bb1.l0:          fdiv.s f3, f1, f2, rup                    
tc.bb1.l1:          call fn2                                  
tc.bb1.l2:          addiw x22, x21, 1584                      
tc.bb1.l3:          fmsub.s f3, f1, f0, f2, rtz               
tc.bb1.l4:          andi x20, x20, 0x3f8                      
                    la x21, data5                             
                    add x20, x20, x21                         
                    lw x19, 0(x20)                            
tc.bb1.l5:          fmadd.d f2, f1, f4, f3, rmm               
tc.bb1.l6:          mulhu x22, x20, x18                       
tc.bb1.l7:          andi x18, x18, 0x3f8                      
                    la x22, data6                             
                    add x18, x18, x22                         
                    amominu.w x20, x19, (x18)                 
tc.bb1.l8:          andi x18, x18, 0x3f8                      
                    la x22, data0                             
                    add x18, x18, x22                         
                    amoand.w x21, x19, (x18)                  
tc.bb1.l9:          jal x19, tc.exit                          
tc.bb2:
tc.bb2.l0:          fdiv.s f4, f1, f0, dyn                    
tc.bb2.l1:          call fn0                                  
tc.bb2.l2:          mulh x20, x18, x22                        
tc.bb2.l3:          andi x20, x20, 0x3f8                      
                    la x22, data0                             
                    add x20, x20, x22                         
                    amomax.d x19, x18, (x20)                  
tc.bb2.l4:          sltu x21, x18, x22                        
tc.bb2.l5:          fmv.d.x f1, x18                           
tc.bb2.l6:          andi x18, x18, 0x3f8                      
                    la x19, data6                             
                    add x18, x18, x19                         
                    fld f0, 0(x18)                            
tc.bb2.l7:          fmadd.s f1, f4, f3, f2, dyn               
tc.bb2.l8:          srli x21, x20, 61                         
tc.bb2.l9:          jal x21, tc.exit                          
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
fn0.entry.l0:       fsgnjn.d f6, f7, f5                       
fn0.entry.l1:       fcvt.l.d x26, f8                          
fn0.entry.l2:       fsqrt.s f6, f9, rtz                       
fn0.entry.l3:       div x27, x25, x26                         
fn0.entry.l4:       andi x23, x24, 129                        
fn0.entry.l5:       sub x26, x25, x24                         
fn0.entry.l6:       fcvt.w.d x24, f5                          
fn0.entry.l7:       mulw x27, x26, x25                        
fn0.entry.l8:       ret                                       
fn0.exit:
fn1:
fn1.entry:
fn1.entry.l0:       mulhu x23, x26, x27                       
fn1.entry.l1:       fle.d x27, f8, f5                         
fn1.entry.l2:       flt.d x23, f6, f8                         
fn1.entry.l3:       xor x24, x26, x23                         
fn1.entry.l4:       xori x23, x25, 1466                       
fn1.entry.l5:       fcvt.s.d f7, f7                           
fn1.entry.l6:       fmv.x.d x25, f6                           
fn1.entry.l7:       fsqrt.d f5, f9, rtz                       
fn1.entry.l8:       mulh x24, x26, x23                        
fn1.entry.l9:       mulhu x25, x23, x26                       
fn1.entry.l10:      ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       sraiw x25, x27, 16                        
fn2.entry.l1:       mulh x26, x24, x23                        
fn2.entry.l2:       fmin.s f5, f8, f9                         
fn2.entry.l3:       fsub.s f8, f5, f6, rne                    
fn2.entry.l4:       mul x23, x26, x27                         
fn2.entry.l5:       addiw x26, x25, 1138                      
fn2.entry.l6:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       fmul.d f7, f6, f5, dyn                    
fn3.entry.l1:       divuw x25, x24, x26                       
fn3.entry.l2:       fdiv.s f9, f7, f8, rtz                    
fn3.entry.l3:       slliw x24, x26, 21                        
fn3.entry.l4:       fcvt.s.d f9, f9                           
fn3.entry.l5:       fsgnjx.d f8, f5, f6                       
fn3.entry.l6:       srliw x27, x23, 7                         
fn3.entry.l7:       ret                                       
fn3.exit:
fn4:
.align 8
fn4.entry:
fn4.entry.l0:       mul x24, x26, x23                         
fn4.entry.l1:       auipc x26, 1576                           
fn4.entry.l2:       mulhsu x26, x23, x24                      
fn4.entry.l3:       andi x26, x24, 898                        
fn4.entry.l4:       sltu x25, x24, x27                        
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
    .dword 0x35646136752d6818, 0xc089cf7d1e19380e
    .dword 0xab17c6c03094a8c, 0xb464250c80c8f73b
    .dword 0x533fe2eb2d0c5131, 0x8ae2dfe68b83a949
    .dword 0x5cb700da91d74df3, 0x683f18ef55f6200f
    .dword 0x1371d5f4b9f16d94, 0x58b584185bf13319
    .dword 0x3d2ea56e607a5f94, 0xdc153d686f03b2fd
    .dword 0xb83fd011c516d140, 0xb876d46fad25b6ee
    .dword 0xeb9561d8e8f28988, 0xee3dd1c729794352
    .dword 0x9598d6710a487b00, 0x63a6ab3369ae85af
    .dword 0xccc16831bf4000bd, 0x43b636422f946118
    .dword 0xae5854a834e5739c, 0x4db931325d9151f2
    .dword 0xf02c604608ccdf88, 0xbeae351e048bdf1c
    .dword 0x618a2cd99bf5543b, 0xbb11f93627c4ff90
    .dword 0x96581b65c0501d26, 0x4856896980113dbb
    .dword 0x7599523efb5359d8, 0xb6a542d0a2ab47a8
    .dword 0x2190a5f52661ae63, 0x8a6b41627ec1bcf
    .dword 0xa5b95eba6e749457, 0x225ac3e18cefc19c
    .dword 0xcd3d938723e5ad, 0x197e4d2e884b677d
    .dword 0xec5347f02e248d63, 0xf5329d1379d3e7a0
    .dword 0x7290aea4b22f23bf, 0x8b7e087e65c171e4
    .dword 0x8358c82ed37ed7d3, 0xc8795673df567d29
    .dword 0x6a5084186d5f60a2, 0x501132dfa76b24fe
    .dword 0x29542bd086b2b132, 0x1da6fd704a198495
    .dword 0xf051518d18e4685b, 0x6c989fd18ae0d86e
    .dword 0x2f6c5774282a0f25, 0x53acac686af82f9
    .dword 0xd8702c3dd11f0b73, 0xc8c10578f0e71e0d
    .dword 0x469971b8ba3a1429, 0x516d0e8bcd097732
    .dword 0xd2fc2a50034dd93a, 0x51914417c7158c5c
    .dword 0xf4014110c6143d7c, 0xac5529240f76c2ce
    .dword 0xa79e8cbf617e156e, 0x8e539246c2a0cfb9
    .dword 0x3eaf97318b9286c5, 0xe01921294df30f53
    .dword 0x55a7cc0f1241fd0a, 0x296d28b66391980a
    .dword 0x8514a19854d08df7, 0xe9c4dcd31a1cb2c4
    .dword 0xe5fffb508beab9bc, 0x5a6a29e2e2f99be6
    .dword 0x9fdc6b4c6962ad09, 0x1cdbeca42cadcbb0
    .dword 0x26e8fa4b7fb4e201, 0xcbd0c4477e398039
    .dword 0x8d81c4f7f0969d2b, 0x698c54bc140059ab
    .dword 0x72bdf57bcec3a734, 0x6cafe36deddffad8
    .dword 0xd957f3c4badd4701, 0x541767ed2c5242b5
    .dword 0xffe362248f92d7a9, 0x890e20f0417d3e87
    .dword 0x29923b9981e3c741, 0xa86f43c682d861f1
    .dword 0x62c1c39769211f67, 0x8b56715d6d217a1
    .dword 0xd1dd5b15105adde3, 0xbbd591640404b06d
    .dword 0xb41db9ed024f9bb2, 0xc827426c6ef03a1c
    .dword 0x2a5bc36a76f28bcd, 0x2790bfd044d33565
    .dword 0x471efd75f1bd75bc, 0x13deb4dc62a5b180
    .dword 0x7cc9d7f6317a35d7, 0xd38292bc8e7540b0
    .dword 0xdd0dd66d37ee4d66, 0x7550760369cb6096
    .dword 0xc5c200d0c3663f64, 0xd06f22afc4e62caf
    .dword 0x5f5a2d57fdd7e54d, 0x605c10fbedf285d5
    .dword 0x2ac0f083b35e091d, 0x592f315a9f9eb5ad
    .dword 0xe9fd8efb638a1086, 0xde6aad1860918da2
    .dword 0x83fbef8e12ea952f, 0xa4867ac3e0ae87b
    .dword 0x8a7eed4cbcde479e, 0x3dd12843622e4fda
    .dword 0x562dcc709c13ea83, 0xc849c8f0ca8670d7
    .dword 0x17992b884aac17b0, 0x34a1bacca35499e8
    .dword 0x1c563296c189dd1, 0x592a14dbd853dc69
    .dword 0x6e79b679d50d2999, 0xe95d0f76d544ff3c
    .dword 0xc7486de3fb6e3ad5, 0xa40913b495be0b27
    .dword 0x5141e89cab3c3bdb, 0x7f0b1ceae8df11ff
    .dword 0xc83385b79f1ef118, 0x45b7c51a34604741
    .dword 0xee241fabb07eb5d0, 0x9272caf71840e085
    .dword 0x7b93e7ea48c643bb, 0x38d5aaa60b6b7d8b
    .dword 0x547045cadbce9d28, 0x250d00a45c50cb2f

    .align 12
data1:
    .dword 0x446fcd772e6db3b5, 0xd5f40d55384d7854
    .dword 0xf19d48871e151074, 0x67aade32d05572f3
    .dword 0x43abee4b3b735454, 0xe1f125407583834d
    .dword 0x6556e55b7247e4ef, 0xfb1971a842c9b53a
    .dword 0x2c758de36bf93639, 0xc866ebd0d9ea36fc
    .dword 0xefe0c0c95671493a, 0x23424f9c03015278
    .dword 0x4e7c2e0a7a7d81d9, 0x610a778be8bbef3
    .dword 0x9af6beecf06f4647, 0xfdcb2b93ebad809d
    .dword 0xda0b0773e87c624b, 0x511910e0f9376925
    .dword 0x16c4f559a997fc42, 0xa170c9ed15f5e2f3
    .dword 0xd214ebf4241ac388, 0xa8de63c103cd7297
    .dword 0x5868d4ad3d086a4c, 0x82c3e7efe3d072d6
    .dword 0xb1b86835a4b5d975, 0x259e028a094541d
    .dword 0x750aac0407a62c60, 0x2dd0f961a9089e4f
    .dword 0xd24a88635592b0ff, 0xfeff315cb06d7909
    .dword 0x52826598712c3929, 0x63e70f20b93cabd5
    .dword 0x6dc7976963b7155b, 0x23d9c34d842b2759
    .dword 0x2756cb04e65640fc, 0x2cdc0cf96445971f
    .dword 0x544542a72a78f5fd, 0x47cdc715863d3ed
    .dword 0x39ce99025cf7a831, 0xb33435180990bd88
    .dword 0x572c738e2bb274a5, 0xd9a0d51dda9d846
    .dword 0xe836cc7dac6775ed, 0x4ad0afe494107e5a
    .dword 0xe75768eb0bd76a83, 0x584769c475b70d74
    .dword 0xbd89e1c55c380495, 0x456b14d25c8e8119
    .dword 0x727b97103ef2f3f7, 0x5762ac252c7249eb
    .dword 0x4b56192811c82734, 0xf57e86a8f894ddc8
    .dword 0x271a67303c432029, 0xb73c8fe6b232ef85
    .dword 0x8cb85ddbd9c52d7f, 0x71377c2e71b8ed18
    .dword 0xc35e562f46cd4965, 0xc92c2cb45b5ebfdb
    .dword 0xb1357a89bc095bde, 0xb4ed2e322628876
    .dword 0x41f1658946857260, 0x991505dd947cfdf2
    .dword 0x71925666034e9357, 0x21b52bc1bb69a139
    .dword 0xca491b0a68996e1b, 0x123f645abb05d45a
    .dword 0x5b54621eb830125c, 0xc2d4cde3c185a4cc
    .dword 0x279dc25c08852e6a, 0xe2e3891336018a3d
    .dword 0xb424b245f53a149d, 0x17f2e23865072b38
    .dword 0x8e552b5c9cdb26de, 0x6accea92feb25c1d
    .dword 0x4cc7a3fe9e2bcced, 0x60cca91aef3be0fc
    .dword 0x6fe62caea0a2dd50, 0x5a3b6f32f136892c
    .dword 0x5d2e55c6a079152d, 0x4032ae6f75d48aeb
    .dword 0xae2c3303eb3b33a3, 0x9f43d8cd08a8397e
    .dword 0x1f20ac5b6ec386b7, 0x6ce5d463621f3eb
    .dword 0xbf9a3483e1a67495, 0xe835940f826f0f41
    .dword 0x316db43c3478d301, 0x2378e94b39d00cdc
    .dword 0x8521d37625a0c524, 0xde3bae7ebf7b71cd
    .dword 0x8fbe0776f09fda8c, 0xf67ab61aaa4d814
    .dword 0x11384d3a85651d86, 0x200ec753e302e82
    .dword 0x9dbce0e9d9f3e3d3, 0x4ca934a2b855104
    .dword 0xbac32ce9401c9e30, 0x2ee906f8995b893a
    .dword 0xe162810bd6f1bc5e, 0x66c775fb68a7ccc9
    .dword 0x6387c73e12ced798, 0x31ff45e39ab610e
    .dword 0x702425d5e8e0ca3e, 0xce91fb87ec598232
    .dword 0xfddd08703462eaf3, 0x6acd69f36f92137f
    .dword 0x70e2c90c9a8015d1, 0xd86b28c83f0e2437
    .dword 0x65313a1b7374ae9, 0x15778c5e8c753b8b
    .dword 0x6a249fdeb3c32450, 0x4c6cd99fc987b218
    .dword 0xde0820265191efc1, 0x42d26789a8b5727c
    .dword 0x3c806ef2c7dcbaaf, 0xbf1912f9d852bfe6
    .dword 0xe08296199f1e23c5, 0x8e184eb6fb5bcf5
    .dword 0x86df26eb90eb7c2, 0x9b6f24455a2d894e
    .dword 0x9bc9adea46f57ae3, 0x5a97f0a2623b6a39
    .dword 0xb88935e5e7e86285, 0x2cb295cc25735b9e
    .dword 0x67ecc49232961f0e, 0x52da71d51565f979
    .dword 0x5bc7b45c00e2c381, 0x45c37ccc089967ec

    .align 12
data2:
    .dword 0xfeb6f1fa4ea688e3, 0xee5220f3fee0af59
    .dword 0x2935aae1fbb7c1f3, 0x307f1c70f9d88b3b
    .dword 0xfb676cdea4681bff, 0xb6123bc7d5691260
    .dword 0x7d5aafa6fdb3245c, 0xd185d2f76a5d43bd
    .dword 0x49c04b83309c7996, 0x196641aa5124eb44
    .dword 0x1ad331934dab58de, 0xdf768ba561b53088
    .dword 0x48d6dd54a2ad7e4c, 0x952eeebdbed218d7
    .dword 0xa65039537314a750, 0x98be32555fbf2006
    .dword 0xce2463ec3bd9b939, 0x4b1485ef58f2f128
    .dword 0x432c96e01f4b4d1e, 0x3cec64300e73bf7c
    .dword 0xd7f7571141228b0f, 0xd89ac44344dab120
    .dword 0x1949a36ff96cb3da, 0xb926964390f93ee1
    .dword 0x3124e4e55a6a3430, 0x1cd74d36bf97f238
    .dword 0x5b3efb12fd84c662, 0x9e6171fd736accbe
    .dword 0xfd6985eb0badaabd, 0x17fd709670899e0a
    .dword 0x8a443a7b41488851, 0xdbd9b8388141c02e
    .dword 0x628da4a195dc640b, 0xa1a2fdf75a2370c3
    .dword 0xf61329181660e29f, 0x4db65469877c3ecc
    .dword 0xd5877d2778098bf3, 0xa3cc23ff5b3e4fa7
    .dword 0xff18357683de2156, 0x1a18cb2a05bbe159
    .dword 0xc6b920c369ffe83e, 0x52531ebc35d4e5e1
    .dword 0x1324387f61f9ea4c, 0x214b2bc87a4d62e5
    .dword 0x1eed3b91d5ccd7aa, 0x3b404b489b96ee2e
    .dword 0xbe99959c4c5b6e1c, 0xa3e6d31471247395
    .dword 0x44e266da31dfe824, 0xdeed848709c02668
    .dword 0xc5905b6aa5db030, 0x270ef575447e4484
    .dword 0xb9c082787bfe1e1, 0xe4209f8fa0cdb189
    .dword 0x7faa0a0cbba332b3, 0xe39cb2a22da17530
    .dword 0xde6c21cc473f9cd3, 0x71f425c489f0605f
    .dword 0x8717af4f37fb24d6, 0x908b88e99771b0fa
    .dword 0xcdd3f2a8dc951ca2, 0x99faf9b34d3aea0f
    .dword 0xb03e1e23de891be3, 0x651691f62fd2960f
    .dword 0x2e2ec0f5fac879fd, 0x82806a78069997a1
    .dword 0x25506a6a01e9ee22, 0x2f7ff37cd9f56c87
    .dword 0xdc65eb7140c1353, 0x4e703b29c8f6612
    .dword 0xdb0183a3c2d87ed6, 0xd10ff7be630d0b7c
    .dword 0xaf8a2c73038fe3d8, 0x1ea488a786226c0
    .dword 0xfa298bef4f00b34c, 0x9532a915efe231b1
    .dword 0x8e63c7a0e6ac95ff, 0xd06215e4e34760ad
    .dword 0xbe2e1e76c35884cf, 0xe358b34de8846d0f
    .dword 0xcd8b2319f6b4282d, 0xbcb8b03567965c8d
    .dword 0xcbcb50d3a499a74f, 0x5e476683b0e68dc9
    .dword 0x5c36137f25889847, 0xea0a0b53ae579ef3
    .dword 0x1d1050afb5560d, 0xfaf8bfaa49a9be7f
    .dword 0xb51fdd4b8938cee, 0xf39bbcdee671ff65
    .dword 0xc7ea5b9562f4c164, 0x306cb8b627cddd69
    .dword 0x15efaeb765a4221, 0xbbd29f47ba157f9b
    .dword 0xb808655644cb3bb6, 0xe10225c0eecccbea
    .dword 0x7af6b8e85700f3ff, 0xc6c6dbae9f63d6c1
    .dword 0xf9b3db101ce91f5e, 0x373e178e9e6f5f7c
    .dword 0x37a40c5f29412717, 0x6c552efd857b0581
    .dword 0x39e1b19a824af635, 0xd3c4f52c6edde474
    .dword 0xe2df054248ab33dd, 0xc74ceab5a783a8ef
    .dword 0x16d8a86da6d5710f, 0x4f33398ff545dec
    .dword 0xba0bd07725c34173, 0xd91541cafb01544e
    .dword 0xfbd02ae177c4e03b, 0x4096b738d7e147f2
    .dword 0x406e5d530cbac6e6, 0x24219378c4ccd80a
    .dword 0x8917110755c1cae6, 0x629e9d5b96e2c71b
    .dword 0xc2d4e44e59294f8f, 0x295f6f800d7a2120
    .dword 0xa87bc7a36f4396ea, 0xd5160c8c4e61f4fa
    .dword 0x4d28e2259ba7f9b0, 0x28e2eb42aa19912d
    .dword 0x7a4d1ed9f3076876, 0xc176efdf8e5a0a3c
    .dword 0x7ed1894434415df9, 0x1d12287285b277e3
    .dword 0x6a08247f866229a1, 0xb70b3ada204cf08c

    .align 12
data3:
    .dword 0x6f4494c3c7714d0e, 0x886eebbd88f97aad
    .dword 0xa9dc4e2d867a3b65, 0xd917d7a7fe308d2a
    .dword 0x21c83e0d20b40de2, 0x2225eeded6aca4e4
    .dword 0x408417fb8f000fa0, 0xb356c2c4224eb3ad
    .dword 0x5b2f783e1e7d4c30, 0x98eb6132b746bd73
    .dword 0x12d761b00d671ad2, 0x38ff6a770a72d651
    .dword 0xe1b7b113a4188289, 0xbc00e5a808fbdd9c
    .dword 0x746557aae8ad1629, 0x6998cbd1fe76db42
    .dword 0x400aad4ea03d74ef, 0xc5596f6889f12a1c
    .dword 0xa3cec2dbc97267f3, 0xabd09cb5216a7499
    .dword 0x43fe59d5afbed067, 0x927315603ef63fe1
    .dword 0x8cea4873ba9a3ffe, 0xfd6afa934e64d101
    .dword 0xc2282de46ffb75ec, 0xa09bcfce8ce90e98
    .dword 0x406d49f806c4df47, 0xdc21ca5aab8ceeb0
    .dword 0xb76b20f4004af0a, 0x618bb89cdf2a1c72
    .dword 0x688341d581c6c918, 0x243a1302d91cd63d
    .dword 0xd23942ecf99b1cda, 0xa728b4e02c18b877
    .dword 0x98d6d961b851850e, 0x4be48dd66de3d445
    .dword 0xe481fa69a5258ad9, 0x10e635fd33437165
    .dword 0x6b821ca91dfa176e, 0xbc4aa697ba97adab
    .dword 0x13e27899c65d3359, 0xa8b3fc70bbe9a876
    .dword 0x5db87ffcdfbaaed4, 0x9992d95298879152
    .dword 0x67def6b757039c2b, 0x10e96d7f6971c518
    .dword 0x3b0d13db375e2bbe, 0xa45a9a037aff6538
    .dword 0x9607bd146b4a2e68, 0x103a08c0462086f9
    .dword 0x16d5f64ddb94307, 0xd93f7117d66fbe56
    .dword 0xced4f537e3203b9c, 0x7456a2a9a51d3137
    .dword 0x2d08d49d74b64ae0, 0xf68c5544fbc3b9b3
    .dword 0x89c61a6d419d9ee2, 0x2ad11d96d68beca7
    .dword 0x6bc4f30938039217, 0xd82214cd73ec7e84
    .dword 0x6120f9f6c0ff2ee8, 0xb1b2ba35586a2d4b
    .dword 0xb7f96484e3251169, 0x3461e50545da56f5
    .dword 0x5e694cbfa732828c, 0xa86129cc31a93d2b
    .dword 0xfa47203a5f8fb698, 0xfcb9dd763517471a
    .dword 0x37a8f8c638204aa1, 0xc40e7f72f516f9a4
    .dword 0x89b801940a1e9bda, 0xf5ae83c08423fca2
    .dword 0x94267c9830ac170b, 0xaf94e8722b31e791
    .dword 0x62ae9d921dff0c55, 0xc6204b7153d54bf1
    .dword 0xa9ff9c3305446172, 0xeb9f090856da0a4
    .dword 0xae784e921b624ce7, 0x2f135dd065df6095
    .dword 0xbc67509bfcc4f4c4, 0x900c580b14af79ed
    .dword 0x1dad33590b801f22, 0xb646a47e13dc1f8a
    .dword 0xf98e3b9c77408ca7, 0x7013567d5abddd8
    .dword 0x4360e950c34baf8b, 0x6e559985e7605194
    .dword 0x52ab91382feb993a, 0xe32db628cab0e69c
    .dword 0xe524b3076d7db74f, 0x9e5ca15f56350686
    .dword 0x8197a693112568df, 0x28ba0668888f02fa
    .dword 0x39182100c85b5a12, 0x6e90d4ee8bc5439f
    .dword 0x33e267b3598b9753, 0x79eb316a7ae5cd65
    .dword 0x67b53bff62e4c4ab, 0x59524417baa0ef9f
    .dword 0x2ebc84541bab19c0, 0xc3923347837f178d
    .dword 0xdb55421f23e6bf1d, 0x3f20b443fbe8b6a3
    .dword 0x442e0f67502bf5af, 0xd7a600fa6d90b695
    .dword 0x4a002f1eb287ad8c, 0xb2c7d6800c43f363
    .dword 0xd3112f80e39ea91e, 0x10ba9e84dec76480
    .dword 0x9e9ebf70e977e45, 0x77c13c958c5b7c99
    .dword 0x3f905a0f575835df, 0x669753b2179473c6
    .dword 0x1c123b433430434f, 0xfe408e454d786cb6
    .dword 0x4872ac8c0207279c, 0xc46206187cd2747c
    .dword 0x3207549c0dc83704, 0x9fb840f0891d47c9
    .dword 0xf25b8a2b89cdd492, 0xbdf76ecb888f6b0
    .dword 0xeece3b50d223e293, 0x25ebb97e449d4834
    .dword 0xfa349300ff9ddf6c, 0xa63fc8ab8ec9c028
    .dword 0x907b899655b84843, 0xd271b8561f615f37

    .align 12
data4:
    .dword 0x750de3c5e1f8c065, 0x53454ae22532183
    .dword 0x799eed90c564629d, 0x1771dc758e1fe26d
    .dword 0x754a8506dea89853, 0xa3d4c437c1a2bd4a
    .dword 0xd1c2712a9d633742, 0x2446230de42c892c
    .dword 0xe2d944c794e42d09, 0x32222506a38f9786
    .dword 0x9a07ac7c150edd36, 0x4d2c07401e4b0a11
    .dword 0xb0a2103e39844d98, 0xaff801e5b6752904
    .dword 0x7a37a0f35a1d2d92, 0xeef1b9dffa82d88e
    .dword 0x2e522a49811780f, 0xa7a35dabfd1fa8f4
    .dword 0xf08067005674691a, 0xbd6495e1604d102c
    .dword 0x74ae8af17b052475, 0xdbfe40aa077b454d
    .dword 0xe0ad916daca99e1b, 0xed81e0c6f8b2fa4c
    .dword 0x10e36fd8388900c7, 0xeeae32e97aa86fde
    .dword 0xa9b4af34eba89b94, 0xe9a8a620d00e8cd0
    .dword 0xd35d8db228d781fb, 0x7fed91f3fcda26a6
    .dword 0xebbb9ef95ad1f430, 0xa6d4ee511714419b
    .dword 0x322a60aa40d6603d, 0x9d49f0e5eacb48c8
    .dword 0xae4738eec211fc99, 0xadeb4a551bf7e467
    .dword 0x9c43bad8c5edd60f, 0xddf0add4336cafb1
    .dword 0x930e9e969903d09d, 0x4f95ac8ccf1da603
    .dword 0x932a1d1df1e2f818, 0x7f9ce93d47e30e4
    .dword 0xb21b51d57d844aa0, 0x8bbcf1ad091a8f01
    .dword 0x7d376a087e3ce9f0, 0x38f7100daef81aae
    .dword 0x70d52fdb28af914d, 0x29547041a2ff7fec
    .dword 0xe234ca96def099a, 0x26036513b252e01
    .dword 0x4126042765a314d3, 0x8a4b0baeba32efe8
    .dword 0x753309c718a22b75, 0xff2f059d81bcda0a
    .dword 0x705176aff514ef79, 0x94cb14d2efa2f222
    .dword 0x2b9fe49a4ee62129, 0xa722118760b5f663
    .dword 0x130eccba54f1aacb, 0x31a4a2a6de7464f1
    .dword 0x45bab75d5a0e40ca, 0xf6f7bbaa8e4967dd
    .dword 0xb616531e17c8248a, 0xc84e274a9b02a3f1
    .dword 0xcc00ea30dce2ef67, 0x811ed378de3a61e2
    .dword 0x3c19df83a1ccb2af, 0x9ad4c9506b8ad997
    .dword 0x521daff78adefc88, 0x6c393e77305a3b92
    .dword 0xccb71dd8920b07b2, 0x2370f0df291fa269
    .dword 0x74dc2b786cbb674f, 0x15c581b08951422b
    .dword 0x934b1d59058829ab, 0xa2f4586a8aaf4005
    .dword 0xe9aeab3fb1864805, 0xb78225c9d4945ab7
    .dword 0x60a88322b7722ba1, 0xe6a0a4e5daa6662d
    .dword 0x733eec24f25c1196, 0xd6cb224435b7e012
    .dword 0xd3736aea363cc94c, 0xa3168d7677225b03
    .dword 0xed21836d2e724222, 0xba3bbeaaf5c6f945
    .dword 0xae425eae968df3fa, 0xf60d4d8d28241644
    .dword 0xace756182bf4d7b2, 0x8189e9991444dfee
    .dword 0x68048980e9a272c9, 0xaf60a77687f2d6fa
    .dword 0x73f80ab74d0d14c0, 0x7d31927ff887bd6e
    .dword 0x164ba7cb9b676d93, 0xca666e8487b2e122
    .dword 0x48c9486794bfb16f, 0x7be2fb97333ce676
    .dword 0x88be1fc76f61a6fc, 0xfb6850569f0283f6
    .dword 0xcee1e7fb97b51c86, 0xfff99f03476d9a4f
    .dword 0x65052c40b1f33111, 0x20bd559dee751d3c
    .dword 0xce31e3ed8dc63b6b, 0x5bd89c16a54d0b88
    .dword 0xc7bd581496b74cba, 0x208953aa89e8baa6
    .dword 0x8d9c6ff222b4291e, 0x7b1dc589a79e2e13
    .dword 0x6467e24c3fa190c7, 0x92f602114c7ac21b
    .dword 0x291269637f5b8036, 0xd33d2d8102720e92
    .dword 0x21913571acba6a9e, 0x8db8de9f65bb5237
    .dword 0xf1851d452a0f276f, 0x4bee8c854c8020ed
    .dword 0x4d9bc13c32f9db0b, 0x64b8543c4e44910a
    .dword 0xbcb2833ca8b9085c, 0x34ec8d7107da834c
    .dword 0xbdca126fd62b74bd, 0xf4198bd8ede5cc32
    .dword 0x744d6302d4aa481, 0xece18d8d61491cfb
    .dword 0xead97b3eed62ff18, 0x70baa7b43399ab3d

    .align 12
data5:
    .dword 0x21be958d8baf2212, 0x34fe780bc801bf4
    .dword 0xb78742d7a1b217fa, 0xaea1f0e07f8ed5b4
    .dword 0xade9dc30704145a4, 0x6b5cf744832547de
    .dword 0xc901838848a52ffd, 0x2dfa511a27aa543c
    .dword 0xf50b2691b14983c3, 0x7838c4703aaef37d
    .dword 0xf945bd8a1b3104ab, 0xc824dc91cdf71736
    .dword 0x7fe217f3e42da9b4, 0xee61b909f41c85b8
    .dword 0xbd76cbc96a01f323, 0xd14c7dfd1a31eada
    .dword 0x533b8338fa9908b9, 0xc40260832694f86f
    .dword 0xc40f146a99e463d1, 0xb7a59a2571414be8
    .dword 0xeb77287c19506ebf, 0xb6b2cb74752fada1
    .dword 0x907c64c820fab969, 0x71767890a64e4858
    .dword 0x17d33f9007977a52, 0x16a9043bdaea4205
    .dword 0x7913a7420e2771e9, 0xf782ad9d8d0e9b0d
    .dword 0xc378a230749b3b6, 0x7317bd719515d53d
    .dword 0x9c18c7270f5de68b, 0xd2c16e3ab9f777bc
    .dword 0x4f211a026a3547e9, 0x1b10ef7ec1f965af
    .dword 0x941343ccd1a2c135, 0xc69823aa8e8fdbb6
    .dword 0x5c65a768dc676c73, 0x9df57e48d5f6aa2f
    .dword 0xd8c04dd22dd8b065, 0xa798a0485166ab76
    .dword 0xcd2c36400089fcfa, 0x6d3c207e856730d8
    .dword 0x9b4d2af5473e1298, 0x9e47fbf93baebca
    .dword 0x3236cfcc62c93063, 0x89366cad6adeb0bc
    .dword 0x2bf6fcff808e83bb, 0x241448935b79148d
    .dword 0x638c8300e1d98324, 0xa15aafeaf5d8cfd1
    .dword 0x356e26508e2c2892, 0xc3fc699d40e12820
    .dword 0x9ce8bd71e0e7d2b7, 0x7b496a3d8a87ce7e
    .dword 0x6f3fbe3767c566c, 0xa963ccc2a27b89ee
    .dword 0x2131439350393b43, 0x52379d4a531cbed0
    .dword 0x376f66a11966cc1, 0x6c3f936528708112
    .dword 0x7c4dc266e84dce04, 0x8b0a15074596db09
    .dword 0x2e53f92ecdfdb512, 0x383d3ec516b21f6a
    .dword 0x85bf334fbebb22b9, 0x9d7e41ff8addb328
    .dword 0xf19b550a20a0d29d, 0x4312d223d2c4e597
    .dword 0x549c1ea392a724d3, 0x24a56901c6633a88
    .dword 0x70acdd233e11bf02, 0x6d3b695c4cdc0231
    .dword 0xc29d68ecdc3fee83, 0xb14c8db693d10783
    .dword 0xce3ee93d059b8f6a, 0x8768dadf68712474
    .dword 0x76b2e3c50cea87b7, 0x65d3a4a2124f8c4c
    .dword 0x80948ecb1a3d33a1, 0xb70631fb847cdb01
    .dword 0xda7bedb5472b3f06, 0x5936bbb107163053
    .dword 0x772440bd23b7a8ce, 0xf50de1fa31236c7b
    .dword 0xa01c6b93fa911cbb, 0x7fd40eaa569b4ea7
    .dword 0x6e6f60fed00ab684, 0x57961264759f435c
    .dword 0xbbf166ff7fb15a92, 0x58d5abab2af7d7ba
    .dword 0xc1e38cd4633e351d, 0x2a1379cea5a4bef7
    .dword 0x5c9950fd9fea4a5a, 0xf8419088f1b9572f
    .dword 0xef22469a8d71e41c, 0x6638d501fab92f48
    .dword 0x8d975894f4f9dee3, 0x5ed70864aa75bf38
    .dword 0xa14628e2e13759cc, 0x6f5ca563261c8a99
    .dword 0x2a388d895c31d2ee, 0xd9127e2ca1894acd
    .dword 0x2cf28720cce82aa9, 0x3533eeeb958a6a57
    .dword 0xf2ec38373c15cbc8, 0x19cbf26d4de9da9c
    .dword 0x890f3ade5970af61, 0x11627a5d24a9389d
    .dword 0x8ef997818102ace7, 0xabe910e4dce0d0f7
    .dword 0xd10e8ee99217164c, 0x97f839f9eebd32d
    .dword 0xd246e867fcbcacc3, 0x8c128fb86339bfd1
    .dword 0x14cc0b5844e6c4bc, 0xd5e9b499aa72a687
    .dword 0x9b43a0d95e2fa63d, 0xecd0e2d17a44c7f8
    .dword 0x2a45b242843651fc, 0xcb4656873851a08
    .dword 0x5470b08fb7bc0f09, 0x3ea792447567953e
    .dword 0x772157bb0bb7be4b, 0x5da30486a4b0f071
    .dword 0x302c2d5d8c179656, 0xe0508b64a46e7b91
    .dword 0x1c47255542ac9d07, 0xc48046a845e69707

    .align 12
data6:
    .dword 0xa8a945d27ee5237a, 0x904f59dd7d63b381
    .dword 0xddbcba68ff254697, 0xef4962e71d43bde3
    .dword 0x1e7460aceb9602d9, 0xbb8154fa0f89c1d3
    .dword 0x2ad782dfc9204a5, 0xfe3e6a1592153707
    .dword 0xb6d9c7ab590cbaaf, 0xbe5d6149d9011c62
    .dword 0x97c3c856f461c521, 0xc5f3fef8b290248a
    .dword 0x16613b2fbeacae87, 0x6b3215960f801338
    .dword 0x91960a68fc136685, 0x8e6ea1e22fd773a6
    .dword 0xfb84af72213a6fef, 0x734fc44837bd92d0
    .dword 0x561d68c913dfe685, 0x16d79f23aa74480f
    .dword 0x957dbbdbf460344, 0xa1d9acd91d109df1
    .dword 0x53193a07e903d6e0, 0xe71b94aea7f6a10
    .dword 0x6b247c88af551a30, 0xed51b5f6ac0875d0
    .dword 0x8ac59623c26fc8, 0x4d9314174790766d
    .dword 0xf27c00fb7b5c6e8b, 0xb5ee7684ae212c99
    .dword 0x8fb3b95d6202e206, 0xd04ccb8d25bd21be
    .dword 0x123d8593bd911df1, 0xd078e905924bb8ac
    .dword 0x479ca7e84fb44e78, 0xe5bb5cf827fc003a
    .dword 0x36e95aeee930694, 0x570f4c374b1b71e4
    .dword 0x532027e4fbf8e88f, 0x5c92ec284788dbde
    .dword 0xe1012c120f6ef549, 0xe869e185e034b6f5
    .dword 0x2f1d0f28713b3b15, 0xa6646643df1bb119
    .dword 0xe3b399931f78de16, 0x82508fc007c7708b
    .dword 0xc7248b9f1c8e7587, 0x2c73d09ccf1a2cfe
    .dword 0x979cdad8cf0d2d1e, 0x1b7fe0d9f26a6fa9
    .dword 0xfe34994845a83892, 0x476563fa51ff792f
    .dword 0xfcf09536790cf9a5, 0xcacec1e87433ced8
    .dword 0xc14052f6ca1468f0, 0x88e0e68e4a1c8e9b
    .dword 0xcc991a2a219040b, 0x5dc496341882bec6
    .dword 0xc2b52aded52e840a, 0x82720e9e77f10a14
    .dword 0xbb1331b1a74738c1, 0xac5bf12eb924f3ab
    .dword 0x85e62207ed87bfaf, 0x18e7a92bb5484f76
    .dword 0x89a79cb31d68d37b, 0x883f94ce6de56ff3
    .dword 0x847eae647df1f352, 0x2b5ffbb8cbc2459
    .dword 0xfac7a47a457b0560, 0xb9664a8499b3eb2
    .dword 0x57f2d031b71e0257, 0xfa0ddf7a3bd378cc
    .dword 0xab20fbec7e113d41, 0xc5e64e819ac56cf5
    .dword 0xc7d44fc32fe69a61, 0x6b6692a504c8a231
    .dword 0x36f28f97b2a11896, 0xe980de333361ce9f
    .dword 0xcf811aca2bdfec63, 0x1d5221bf5cf896dc
    .dword 0xbac09e004678de63, 0x31695dee66ccd649
    .dword 0x290ac771e67f060d, 0x63a93c0e28bf92be
    .dword 0xfc8367fad7f32c90, 0x777bb76f39178257
    .dword 0xb5f8c79e44247490, 0x5c2bb433ce4a7f13
    .dword 0x67ffc23bad2bbf4, 0xd03e6a2ea310eb8
    .dword 0xa007641ec335db22, 0x45036b819531c3d9
    .dword 0x43d298f7c68e14d9, 0x188073e43fd0c4c1
    .dword 0x380e1489efa2fdcb, 0x65914f93761d0af4
    .dword 0xfd595c2bbd4c9af0, 0xb1070862b77c918a
    .dword 0x3f465bb55ef88c98, 0x51a5a189e7cce5da
    .dword 0xb82da700deb6c7ff, 0x24f6bb2ec52554cd
    .dword 0x554fc98dd6b8c067, 0xe890ea3c86cdb8bf
    .dword 0x31a1d3f301f19b1e, 0x8dc879e5861ecadd
    .dword 0xea865cbaa3ad3a51, 0x237ed115cf821728
    .dword 0xb5c4e0e1508543ab, 0x3bb6b82566a00f2a
    .dword 0x764934c41510ac0a, 0x30e48b1c962b5b11
    .dword 0xc97ad907465c5bad, 0xa84f3c3b9763adad
    .dword 0xddbe8765a1eabab1, 0x733e1e4cb95ed580
    .dword 0x7534cac80714c472, 0x12e1efcedf8e767c
    .dword 0x39d57839b8d53cc7, 0xd435152c66530c2b
    .dword 0xeec4f44258c682e, 0x387496fa5fcb089b
    .dword 0x6404ec405098f6fb, 0xaeed8aa2a7bfaec6
    .dword 0x92fa9dca4e4464fe, 0x6c0a74ad2a85f89c
    .dword 0x8f767219f64d47d0, 0x605ab1dd1558c6d6

    .align 12
data7:
    .dword 0x9286b4cf74a8c18c, 0x3671fe4805a8df2f
    .dword 0x246b7d5b17b30907, 0x8dcb9e9b525715d0
    .dword 0x1b91756468895a34, 0x89ded1caace0bde5
    .dword 0xce5486ab607cedba, 0x2e739b8a15a7d60f
    .dword 0x84729e30a2697cf0, 0xb510e994ee7a85bd
    .dword 0x8b9b138c6c52c461, 0x8e607928a0508768
    .dword 0x2b7f73b8035a4a24, 0x5641cbe24507aa1e
    .dword 0x6e108adf3111837e, 0x9ab69d118eb12c45
    .dword 0xdfcc479956a1ba0c, 0x47c558cd4b872f23
    .dword 0x42bdbca8fd6dbc75, 0xcd934a1453bb1220
    .dword 0x46aecc8ae4ec5b25, 0xc3014ce1b19b20c
    .dword 0x7713f9386bb513fb, 0x58d85bd7631f1a51
    .dword 0x69c5459b357535f, 0x60ed5a6fee2b135a
    .dword 0x31da876d26322b07, 0x8f8c6c475b8e459e
    .dword 0x8ef50141052bffe0, 0x61d212e238205866
    .dword 0xd5946c46f63d56ba, 0x94f63eebd667ef5c
    .dword 0xd3fb3792cafe562f, 0x227972a0ccf7c7a1
    .dword 0x3daaf723c3c8b05e, 0x62494df32ba9ef5a
    .dword 0xfd7dc5bf58edbe23, 0xa37d494a17bcc428
    .dword 0x90992cdf0555a0d9, 0xb45c36fe15555b08
    .dword 0xc8181ad58b67e761, 0x4e9a03ed078d220b
    .dword 0x5be05c9082255eca, 0xb648b7e60689245
    .dword 0x51792a29e7a0d3e6, 0x12d6713477ab4f82
    .dword 0xa65f0863b1426950, 0xff1a4ec82cc69418
    .dword 0xeb79ff7ab50a10a5, 0x4c0032277be2f941
    .dword 0x2b9e775cc54a4a0c, 0x8c63496ed4e580f4
    .dword 0xfd982fc9c4645d07, 0xd2d027f0e8d0e33e
    .dword 0x8aff861ff8244e32, 0xca3a5a44ac9e8f2f
    .dword 0xaf861aed1f151ba1, 0x99776de4a9a88eab
    .dword 0x26699ce701e1527b, 0xc86eccb8a18a44d3
    .dword 0xfdc89e097576ae4, 0x93a9be3d0ada66dd
    .dword 0x96bae544ef4f5626, 0xa7d849b64ece8f2
    .dword 0x4a6f19da780a2bb8, 0xf8c109c0070fd0d9
    .dword 0x5e68c013f0fce3b9, 0x947b397d99154fa5
    .dword 0x7a6cb47dd318523e, 0x110ec9e3ca3aa1
    .dword 0x19a7fb9792f64cdb, 0xd23c6f3bee0ab882
    .dword 0x8f0e760ad5fe251, 0x2f9e760ee71c9a0c
    .dword 0xdd141bbc2bbdf76e, 0x1f3a3c8d3dc7f058
    .dword 0x831416438aab3a02, 0xceaa5f5f8520bb9a
    .dword 0x5181374474b300f1, 0xc05fc4a8d176c65
    .dword 0x499c68b972b0f814, 0x959458b5e3d5d161
    .dword 0x301e2d01467d1550, 0x6f60735651831fc5
    .dword 0x34a45f7ef1d3ad2e, 0x5f90ebfedf3e9607
    .dword 0x9afa357b1868feed, 0x9bbf108baaaafc47
    .dword 0x960cf89f83c9fa08, 0xbd861a0c0a3ce0e4
    .dword 0x75eaae526dc5a546, 0x8bfc3e2d076b25ba
    .dword 0x38a0420cc654ac15, 0x8f74d33531532caa
    .dword 0x31c8c4f76bb1e6a2, 0xe83f788fb086bd79
    .dword 0x2db0d0b1b7ce3190, 0x4e189c208db14ad6
    .dword 0x12af69182cd52fd0, 0x6b6f8d5d84f9b77b
    .dword 0x22a627cf5cdaab88, 0x50cdbfccf6512e46
    .dword 0x29347ba9a735c2a5, 0x76b6177fe9b75ee2
    .dword 0xa3bfa623f8b5b188, 0xe87d1d7a411be520
    .dword 0x5f0e6e3fd3166b03, 0x64e2db180787a52f
    .dword 0xc05d61e9f631e0, 0x5ae00878c2229753
    .dword 0x12eb07652c39ca4b, 0x5abf040f4741112e
    .dword 0x2b25678fba51acca, 0xcffc9bb2e461b21b
    .dword 0x8b99128177688d1, 0x19bba1e15cc56adb
    .dword 0x9460d5b31dde14af, 0x25f811d26346c21f
    .dword 0x42e042f6ff4acf0a, 0xc20f329017b6a9f6
    .dword 0xae8932717f8f372e, 0x3c7329c3ced14654
    .dword 0xd2ac834d54b4430, 0x249ed334e22796ac
    .dword 0x1a85ca2048d8e566, 0x93aa59b62595912a
    .dword 0xc05e02cd71096568, 0x6fac7808f8f2b7a6


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0xb2e33b0594b89bc9, 0xd5ebd71b56d8b6de
    .dword 0x3b4259bd5508b580, 0x115e538f3f371400
    .dword 0x6376a83f1bdfb77, 0x5d4004424e2f6975
    .dword 0x63e878b699f42b66, 0xc97350f532aa8b80
    .dword 0xa8160a561b47ccbe, 0xa16f2713363f623c
    .dword 0xf7d36ab7e8c3a584, 0xae72fd8be48dbb16
    .dword 0x38046437b130e3ca, 0x67ac7d5e8b251f13
    .dword 0x401b8990ce5f3c20, 0x628a2b36bdb574f1
    .dword 0xe3a072ae2d65c1da, 0x4a19d3f26a63f091
    .dword 0xfe64c5918363dae9, 0xe5188abb94983546
    .dword 0x692eb48f2e88092e, 0xe338bb4b03666176
    .dword 0x535f9c4c9b80946, 0xbd9fbd2e084957f9
    .dword 0x4fff30f75fa1c09a, 0x969abb51ade60a19
    .dword 0xa81ab6b4846b2ec4, 0x90d5a688e758297e
    .dword 0x9d5c6d3ebc3ed0dc, 0xb7ac5d429bd62d9f
    .dword 0xf44d1fba8cfe452a, 0x5040d156f3bff7db
    .dword 0xe6db05a66722f990, 0xa3845c5d2cfd75ee
    .dword 0xf0989101a5b2c0a3, 0x7dbde6fbb1cffefc
    .dword 0x3a135ff576477973, 0xf95099ce47c5ce32
    .dword 0xa7d4efe90b28dcf7, 0x58b152992584e5c5
    .dword 0x9736dc25ce26b6b8, 0xab461486bbd99747
    .dword 0x5415bfd322682d55, 0x956452bdff77811f
    .dword 0xf112f088e22312b4, 0xd9334a8e8b072dfa
    .dword 0x3e2512c607f04b4a, 0x7313aa1679439359
    .dword 0x553bec0db3b789f4, 0xfc14fc78affdabcc
    .dword 0x6f1a1d4c7cf0a7ef, 0xaf7f145713039a62
    .dword 0xc7980d910fcba03d, 0x614f5430364d61c9
    .dword 0x91997f7ccc4912f, 0xea900780406a5725
    .dword 0x71825befdf0c1966, 0x92c6981f9ae633b4
    .dword 0x6503f04cea8fa689, 0x630c0b030742889e
    .dword 0xd3308266397ed369, 0xd5fe7f676e652343
    .dword 0xbb257ec1cf3c73c6, 0x5b1ce95d40a34809
    .dword 0xb6d33dc744d1e56, 0xb431303151baed40
    .dword 0x1e5ab6de57d4c928, 0x4f4f40c474e180d4
    .dword 0x1ba635f660547f99, 0x409878b6e776662d
    .dword 0xac91156feb6a28ae, 0xbbac86a6667f2114
    .dword 0xb12b1ec97901668e, 0x1424be752403daa7
    .dword 0xc07d00d1faf4b723, 0x1e48d1c4d50c1e3d
    .dword 0xbe2aef5ae815dbdc, 0xf7783456d7b94f43
    .dword 0x2de3b71831b5398b, 0xf4b667463035a461
    .dword 0x532c2a158ba29a2a, 0xabc014bf873f2d36
    .dword 0x3c3d6ba725c03fa8, 0xc6a2b54c6e79eab5
    .dword 0xe253c869f1102970, 0xc1c7ec71d710571a
    .dword 0x75322aa0795b9673, 0x7090cf1e6e432962
    .dword 0x51048be430967df4, 0x61bafec6dfe111c4
    .dword 0xe3cf3fd07ed4f462, 0x1b7c4119b2329665
    .dword 0xa0b575a1c78dd090, 0x5e675f73ae412ea0
    .dword 0xebc0e2f65213e91f, 0xa5f3241680bb05d9
    .dword 0x1a6ea1731ed30d56, 0x239b6ebeedddeb4d
    .dword 0x44e30b4cd0f40eed, 0xf28ccf0c2568798c
    .dword 0x31763ba71a7db65f, 0x38b5f637611af11
    .dword 0x388265b8ae065e4e, 0x1c93ccb7d9e563dd
    .dword 0x6b90ea58f9a0c45f, 0xe6ebccb1981766e3
    .dword 0xeb921d73adbdcf83, 0xa04f7c6ea44374f3
    .dword 0x645a6d17256aff73, 0xb5ab621a1fd6bdfe
    .dword 0x1450f65d87d4353d, 0xe6db95df4c48e9d0
    .dword 0xeddfc95332036326, 0x4ab1762d06e6e6c6
    .dword 0x5b0aaacaedfa3301, 0xc070f7f766438ecd
    .dword 0x625d568d054c6664, 0x350d0231f064f0e5
    .dword 0xa3feed5e6bff0e4f, 0x93a86ef3cb91590d
    .dword 0xaa380dd4bacfd004, 0x928d9d437a436784
    .dword 0x62c5a9089d551e51, 0xe8334546b769edee
    .dword 0x6cc5d2e3e566060c, 0x957884b25109647a
    .dword 0x890702c15f3dfccf, 0x2249f0928514be93
    .dword 0x0000000000000000, 0x0000000000000000
