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
                    la x20, data2                             
                    add x19, x19, x20                         
                    fld f0, 16(x19)                           
pfx.bb0.l1:         andi x22, x22, 0x3f8                      
                    la x19, data3                             
                    add x22, x22, x19                         
                    fld f1, 8(x22)                            
pfx.bb0.l2:         andi x19, x19, 0x3f8                      
                    la x18, data5                             
                    add x19, x19, x18                         
                    fld f2, 0(x19)                            
pfx.bb0.l3:         andi x21, x21, 0x3f8                      
                    la x20, data2                             
                    add x21, x21, x20                         
                    fld f3, 24(x21)                           
pfx.bb0.l4:         andi x18, x18, 0x3f8                      
                    la x19, data5                             
                    add x18, x18, x19                         
                    fld f4, 16(x18)                           
pfx.bb0.l5:         andi x22, x22, 0x3f8                      
                    la x19, data2                             
                    add x22, x22, x19                         
                    fld f5, 8(x22)                            
pfx.bb0.l6:         andi x22, x22, 0x3f8                      
                    la x21, data7                             
                    add x22, x22, x21                         
                    fld f6, 0(x22)                            
pfx.bb0.l7:         andi x19, x19, 0x3f8                      
                    la x20, data1                             
                    add x19, x19, x20                         
                    fld f7, 24(x19)                           
pfx.bb0.l8:         andi x21, x21, 0x3f8                      
                    la x20, data4                             
                    add x21, x21, x20                         
                    fld f8, 8(x21)                            
pfx.bb0.l9:         andi x19, x19, 0x3f8                      
                    la x20, data3                             
                    add x19, x19, x20                         
                    fld f9, 0(x19)                            
pfx.bb0.l10:        addi x18, zero, 1838                      
pfx.bb0.l11:        addi x19, zero, 1522                      
pfx.bb0.l12:        addi x20, zero, 888                       
pfx.bb0.l13:        addi x21, zero, 1033                      
pfx.bb0.l14:        addi x22, zero, 220                       
pfx.bb0.l15:        addi x23, zero, 60                        
pfx.bb0.l16:        addi x24, zero, 188                       
pfx.bb0.l17:        addi x25, zero, 1026                      
pfx.bb0.l18:        addi x26, zero, 324                       
pfx.bb0.l19:        addi x27, zero, 1661                      
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
prp0.entry.l0:      fmin.s f0, f3, f4                         
prp0.entry.l1:      bge x18, x22, prp0.bb1                    
prp0.entry.l2:      fdiv.s f4, f0, f1, rup                    
prp0.entry.l3:      bge x18, x20, prp0.bb0                    
prp0.entry.l4:      divw x19, x18, x20                        
prp0.entry.l5:      fcvt.lu.d x18, f2                         
prp0.entry.l6:      bgeu x21, x18, prp0.bb1                   
prp0.entry.l7:      fsgnjn.s f0, f4, f1                       
prp0.entry.l8:      mulh x21, x18, x20                        
prp0.entry.l9:      call fn3                                  
prp0.entry.l10:     jal x19, prp0.bb1                         
prp0.bb0:
prp0.bb0.l0:        slli x21, x20, 61                         
prp0.bb0.l1:        call fn1                                  
prp0.bb0.l2:        sraiw x22, x21, 12                        
prp0.bb0.l3:        call fn3                                  
prp0.bb0.l4:        fcvt.s.w f3, x19                          
prp0.bb0.l5:        jal x22, prp0.bb2                         
prp0.bb0.l6:        blt x18, x22, prp0.bb1                    
prp0.bb1:
prp0.bb1.l0:        mulw x21, x18, x19                        
prp0.bb1.l1:        srai x20, x22, 53                         
prp0.bb1.l2:        fsgnjx.s f0, f2, f3                       
prp0.bb1.l3:        sltiu x22, x21, 1353                      
prp0.bb1.l4:        srliw x19, x20, 12                        
prp0.bb1.l5:        addiw x20, x18, 386                       
prp0.bb1.l6:        fnmsub.s f4, f2, f0, f3, rdn              
prp0.bb1.l7:        fsub.s f2, f3, f1, rtz                    
prp0.bb1.l8:        blt x18, x20, prp0.exit                   
prp0.bb1.l9:        bltu x22, x18, prp0.exit                  
prp0.bb2:
prp0.bb2.l0:        remw x22, x21, x20                        
prp0.bb2.l1:        call fn4                                  
prp0.bb2.l2:        and x20, x18, x21                         
prp0.bb2.l3:        slti x18, x19, 1268                       
prp0.bb2.l4:        fadd.d f0, f2, f3, rne                    
prp0.bb2.l5:        sraiw x19, x21, 5                         
prp0.bb2.l6:        call fn1                                  
prp0.bb2.l7:        fcvt.d.s f0, f0                           
prp0.bb2.l8:        bge x18, x20, prp0.exit                   
prp0.bb2.l9:        fcvt.s.w f2, x19                          
prp0.bb2.l10:       la x18, prp0.exit                         
                    jalr x20, 0(x18)                          
prp0.exit:
pre_attack0_end:
    call pre_attack1


    .section ".text.preattack1"
    .global pre_attack1
    .align 2
pre_attack1:
prp1:
prp1.entry:
prp1.entry.l0:      mulhsu x19, x22, x21                      
prp1.entry.l1:      fmax.s f4, f3, f1                         
prp1.entry.l2:      slti x18, x21, 1286                       
prp1.entry.l3:      flt.d x20, f4, f1                         
prp1.entry.l4:      beq x19, x22, prp1.bb0                    
prp1.entry.l5:      auipc x19, 2392                           
prp1.entry.l6:      bltu x20, x22, prp1.bb1                   
prp1.bb0:
prp1.bb0.l0:        srliw x20, x18, 11                        
prp1.bb0.l1:        fnmsub.d f1, f4, f0, f2, rdn              
prp1.bb0.l2:        sltu x21, x19, x20                        
prp1.bb0.l3:        fsgnjn.s f0, f4, f2                       
prp1.bb0.l4:        call fn0                                  
prp1.bb0.l5:        bge x19, x18, prp1.bb2                    
prp1.bb1:
prp1.bb1.l0:        slti x19, x22, 1868                       
prp1.bb1.l1:        remu x19, x22, x18                        
prp1.bb1.l2:        fsgnj.s f0, f2, f1                        
prp1.bb1.l3:        fmin.s f1, f2, f0                         
prp1.bb1.l4:        call fn4                                  
prp1.bb1.l5:        call fn3                                  
prp1.bb1.l6:        sub x22, x19, x18                         
prp1.bb1.l7:        flt.d x20, f0, f4                         
prp1.bb1.l8:        fmul.d f1, f2, f3, rup                    
prp1.bb1.l9:        la x18, prp1.bb2                          
                    jalr x21, 0(x18)                          
prp1.bb2:
prp1.bb2.l0:        fmv.d.x f3, x20                           
prp1.bb2.l1:        mul x22, x21, x19                         
prp1.bb2.l2:        beq x21, x19, prp1.exit                   
prp1.bb2.l3:        call fn2                                  
prp1.bb2.l4:        divu x19, x18, x22                        
prp1.bb2.l5:        rem x20, x19, x22                         
prp1.bb2.l6:        fcvt.wu.s x22, f0                         
prp1.bb2.l7:        jal x18, prp1.exit                        
prp1.exit:
pre_attack1_end:
    call attack


    .section ".text.attack","ax",@progbits
    .global attack
    .align 2
attack:
tc:
tc.entry:
tc.entry.l0:        mul x22, x18, x20                         
tc.entry.l1:        sub x22, x18, x20                         
tc.entry.l2:        divuw x21, x22, x18                       
tc.entry.l3:        fclass.d x21, f2                          
tc.entry.l4:        bge x18, x22, tc.bb0                      
tc.entry.l5:        fmsub.d f2, f4, f0, f1, dyn               
tc.entry.l6:        bge x22, x19, tc.bb1                      
tc.bb0:
tc.bb0.l0:          call fn3                                  
tc.bb0.l1:          mulw x21, x19, x18                        
tc.bb0.l2:          fcvt.w.d x21, f0                          
tc.bb0.l3:          srai x21, x18, 45                         
tc.bb0.l4:          andi x22, x22, 0x3f8                      
                    la x21, data0                             
                    add x22, x22, x21                         
                    lr.d x18, (x22)                           
tc.bb0.l5:          fcvt.d.lu f2, x21                         
tc.bb0.l6:          add x22, x20, x21                         
tc.bb0.l7:          andi x20, x20, 0x3f8                      
                    la x22, data7                             
                    add x20, x20, x22                         
                    amominu.d x18, x19, (x20)                 
tc.bb0.l8:          jal x19, tc.bb2                           
tc.bb1:
tc.bb1.l0:          beq x21, x22, tc.bb2                      
tc.bb1.l1:          call fn0                                  
tc.bb1.l2:          xor x20, x21, x18                         
tc.bb1.l3:          sltiu x19, x21, 1832                      
tc.bb1.l4:          fcvt.l.s x21, f2                          
tc.bb1.l5:          call fn3                                  
tc.bb1.l6:          fcvt.d.lu f4, x22                         
tc.bb1.l7:          bltu x20, x19, tc.bb2                     
tc.bb2:
tc.bb2.l0:          andi x22, x22, 0x3f8                      
                    la x18, data6                             
                    add x22, x22, x18                         
                    sh x21, 26(x22)                           
tc.bb2.l1:          andi x21, x21, 0x3f8                      
                    la x18, data4                             
                    add x21, x21, x18                         
                    sc.w x20, x22, (x21)                      
tc.bb2.l2:          andi x21, x21, 0x3f8                      
                    la x22, data5                             
                    add x21, x21, x22                         
                    lr.d x19, (x21)                           
tc.bb2.l3:          mulhsu x18, x19, x21                      
tc.bb2.l4:          andi x22, x22, 0x3f8                      
                    la x21, data1                             
                    add x22, x22, x21                         
                    amomaxu.w x20, x19, (x22)                 
tc.bb2.l5:          andi x22, x22, 0x3f8                      
                    la x19, data4                             
                    add x22, x22, x19                         
                    fsw f1, 24(x22)                           
tc.bb2.l6:          fcvt.s.w f4, x19                          
tc.bb2.l7:          fmv.x.d x19, f0                           
tc.bb2.l8:          la x18, tc.exit                           
                    jalr x20, 0(x18)                          
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
fn0.entry.l0:       feq.s x26, f9, f8                         
fn0.entry.l1:       fmax.s f8, f5, f9                         
fn0.entry.l2:       feq.s x24, f7, f8                         
fn0.entry.l3:       slti x27, x24, 571                        
fn0.entry.l4:       sub x25, x24, x23                         
fn0.entry.l5:       ret                                       
fn0.exit:
fn1:
.align 8
fn1.entry:
fn1.entry.l0:       fcvt.s.d f6, f6                           
fn1.entry.l1:       fmax.s f6, f7, f5                         
fn1.entry.l2:       feq.s x27, f8, f6                         
fn1.entry.l3:       fsqrt.d f6, f7, rdn                       
fn1.entry.l4:       fmin.d f5, f7, f9                         
fn1.entry.l5:       fnmsub.d f9, f7, f8, f5, dyn              
fn1.entry.l6:       fsgnjn.d f6, f9, f8                       
fn1.entry.l7:       xor x26, x25, x23                         
fn1.entry.l8:       feq.d x27, f9, f7                         
fn1.entry.l9:       fcvt.s.d f8, f8                           
fn1.entry.l10:      ret                                       
fn1.exit:
fn2:
fn2.entry:
fn2.entry.l0:       mulhu x25, x27, x24                       
fn2.entry.l1:       rem x25, x24, x26                         
fn2.entry.l2:       fcvt.s.d f6, f6                           
fn2.entry.l3:       fcvt.d.lu f5, x25                         
fn2.entry.l4:       flt.d x26, f9, f6                         
fn2.entry.l5:       ret                                       
fn2.exit:
fn3:
fn3.entry:
fn3.entry.l0:       or x23, x27, x25                          
fn3.entry.l1:       srl x23, x26, x25                         
fn3.entry.l2:       fsgnj.d f6, f5, f8                        
fn3.entry.l3:       fsgnjn.d f6, f7, f9                       
fn3.entry.l4:       fence.i                                   
fn3.entry.l5:       fmin.s f9, f8, f5                         
fn3.entry.l6:       fsgnj.s f9, f7, f6                        
fn3.entry.l7:       fadd.s f7, f5, f6, rup                    
fn3.entry.l8:       srliw x25, x23, 25                        
fn3.entry.l9:       ret                                       
fn3.exit:
fn4:
.align 8
fn4.entry:
fn4.entry.l0:       fsub.d f7, f8, f6, rne                    
fn4.entry.l1:       fsgnjx.s f6, f9, f5                       
fn4.entry.l2:       fcvt.l.s x27, f5                          
fn4.entry.l3:       fcvt.s.wu f8, x26                         
fn4.entry.l4:       fmax.d f6, f9, f8                         
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
    .dword 0x46c2e932c9751fe6, 0x9dba24e8cba2b4d3
    .dword 0x8c5355eb2b5d3d97, 0x6ecb1eb2524c4c06
    .dword 0x20034b9ad68f5db2, 0x95d543758ea78cfd
    .dword 0x27c74dde261c65fc, 0x3be03870314d4063
    .dword 0x4c81e8a63f77eeb6, 0xdde6c67693f1e1b1
    .dword 0x5d6a25ef7b673b93, 0x9352fd2466c84d3
    .dword 0xfc099d26a0144a5f, 0xa4ec5735c8c9ce42
    .dword 0xaf5ca9860c666462, 0x5db8cc9b236e1052
    .dword 0x9ee53714fbc00540, 0xa3f691a0b98153b4
    .dword 0x29dd1794339351fb, 0x3c5d847058657988
    .dword 0xed8e6277baa42798, 0xd0e8d2de06e29cd2
    .dword 0x7165d8a7e4dc611d, 0x457d2225ad51cfed
    .dword 0x6c46c58de2c2112f, 0x1bc66ff9d4d0bcbd
    .dword 0xba6ae260018fb2c9, 0x15a1bdba9fc9c96f
    .dword 0x4f6b830e215aab4a, 0xb3d007bcf5b10027
    .dword 0xcc9ffc04d7e612ac, 0xbd682252895ec51f
    .dword 0xa558321b84f322f7, 0x7eb3c1787e1ed1c1
    .dword 0xece52559677e61a2, 0xf56cfe29858d61b
    .dword 0xa6edc679e551c5e8, 0x8d081d17cce4f015
    .dword 0x97013dceeee1dd33, 0x99475e12ca1cd754
    .dword 0x9af95554633c836a, 0x6102ef421d7f93d8
    .dword 0x237fdaba305f1c7b, 0x6c37176b25fc08c0
    .dword 0x67327927b2023c63, 0x5a84f986524fbd67
    .dword 0x38a35f7382af47dc, 0x434a4e6e36891356
    .dword 0xcd3646d1852e1328, 0xbc91f1b485721934
    .dword 0x847485f90d6490ec, 0xd4950ae5e439df6
    .dword 0x7e2a28335da9bffe, 0x4d2bd05827f063bd
    .dword 0x6def587a370c2ca0, 0x5c168c606aa2c252
    .dword 0x2b915665fb5c1bb5, 0xa291856fec787f01
    .dword 0xe7b980b99ca9d9be, 0xc16692c5f4d8e03d
    .dword 0xcbae4e2835a11af8, 0x776ddb58d996d96c
    .dword 0xed65907f2bdf1e2c, 0x3a47e862dac3ae0d
    .dword 0x2dc8b123e44519f0, 0xdbce38761b42faa8
    .dword 0x4dcab1ab12f9a836, 0xf54da39eaff4d06f
    .dword 0xf2fd4cb4fba85de4, 0xa00734c43c424cd0
    .dword 0x2e333c295d7ba63c, 0x6377fe2ddb3e5837
    .dword 0x1d03934a79fe3c54, 0xbcd004166dcd37f4
    .dword 0x877ef99d40575b29, 0xd11f97938b3787d0
    .dword 0x10beb36c8749f2ba, 0x6ff3dfe4ebe7a23b
    .dword 0x2666a09f864ec011, 0x67ebb52adc916fe5
    .dword 0xdea4112e54158c3b, 0xae012941a3d00717
    .dword 0xf779ff660474e0c7, 0xd412c0eb69932a0f
    .dword 0x8946b5040a6a94dd, 0xe3ae27e5dedc5848
    .dword 0x8dfbd8f9322025f7, 0x10197d2ab701d2b4
    .dword 0x88797b63edc5747c, 0x917c0dd62fd123ec
    .dword 0xe9dd291c05325dfd, 0x7c48c1017f18eb85
    .dword 0x39bd93601ad66994, 0x8ea2523cf3a73a7
    .dword 0x4cf0a72719219b5b, 0x5b01b2b120bc57a8
    .dword 0x654fd8587df0364e, 0x5041a04060f31e25
    .dword 0xd56e44dee5a8f0b6, 0xd6434c3fd0a54d99
    .dword 0x1c34b57c5b89d8fc, 0xffa0b4d94ad44c03
    .dword 0x681371fcb515d2d1, 0x1ae4375883799fc3
    .dword 0x5d23b8f5870a5a93, 0xdebb0f1a1e455aaa
    .dword 0x5b7cfa2d007534af, 0xb59d07e4f0970ee9
    .dword 0xd49458acbc8f31fc, 0x6c2ddb6ba35ba9f7
    .dword 0xbb1c6f56597fc76a, 0x892948331e154edb
    .dword 0xf6c20f7fe81c1aba, 0xba2fcdb7b938a62a
    .dword 0x5fa7454acd6625ac, 0x3b662d4be0f7ee74
    .dword 0xf3cfb23246894bb6, 0x4f890d650fb4746b
    .dword 0x5a24e77cfbd54a3a, 0x8391febf07a3f8c0
    .dword 0x922f4a2bbd92cb26, 0x162aad7f2723a9c7
    .dword 0xda2f98b8ba0bfc3e, 0x5dac410dad7fb8f9
    .dword 0x5cad30f6b68cb97a, 0xb826609c9af0765e
    .dword 0xf63bbde53404b7b1, 0x4e11817ebcd7b47c

    .align 12
data1:
    .dword 0x3f3b92561f7b2e8b, 0x109e34b9e310c6a4
    .dword 0xa1df9c889b753076, 0xb0fc598ba40a1050
    .dword 0x337e8884611200dc, 0x4fae01cf78eace6c
    .dword 0xfbf40948aacd48d2, 0xec7c4959630a9feb
    .dword 0xfd4e44be661c5314, 0x651cfb90ef0c39ca
    .dword 0x71df8a5a79d46e37, 0x9a3c0c3eec36daf2
    .dword 0xb27d2dcac8f99709, 0x7fb252792b5acbaf
    .dword 0x80d2823c93a30c7b, 0xf1c5f00226cf3c53
    .dword 0xb0c358deee8a362, 0xb63dea7a34980bf2
    .dword 0xc3ebd392f5d7f8e6, 0x15be2bb3c2b58dad
    .dword 0xb8ee44321bb7dd72, 0x43d0babcb401815a
    .dword 0xd2704d1cf280ff7, 0x8d89df85f767ba2a
    .dword 0x65130508994f6873, 0x83a1674858712e9a
    .dword 0x68feac0a425e60e7, 0x42f1225bd8b77093
    .dword 0xb75d86f23520f018, 0xcc3c48158904d1b4
    .dword 0x1eade11749310170, 0x90c0143c205427ef
    .dword 0x91cb837ec99cfb38, 0xd5e6d37d052de782
    .dword 0x3d77276124693c3f, 0x21393ab39cc27a11
    .dword 0xdb40cd8ef2a59b16, 0x44e72c769faaedfe
    .dword 0xf8e9065b1c49e792, 0x17ef4b0be67cd02c
    .dword 0xab1bde72a0aee6df, 0xe6ae83f3ba65618e
    .dword 0x84cb3556901932e, 0x561b10350a3c0bc3
    .dword 0xc6f7f0b7e2a10058, 0x7735405c627e9f1d
    .dword 0xccd32711830feeb5, 0x81ea74f3991cf210
    .dword 0xbe9dcfa115f74e5e, 0x796f2d51e46b684b
    .dword 0x9e52413655ad25ef, 0x327fee05988b98b3
    .dword 0x263ad798c297077d, 0xe88b2e29f7ec5655
    .dword 0x5e676e007e0bfa4b, 0xc8d369568085500d
    .dword 0xfe665c4baebb368c, 0xdf59b5b757e249d8
    .dword 0xa7eb6747a8e3113, 0x572c5b28ad03bc0b
    .dword 0x9b2fefe6dc705b4, 0x92433504feb158dc
    .dword 0xac3a127edd7bac82, 0xecb79ad284149de8
    .dword 0xa9af8cc7db25ce99, 0xf15381d746875969
    .dword 0x88915aa009c8f37c, 0x6a36c10f52fe3276
    .dword 0x6e2fecf9d5e3b0d4, 0x7fabbb440a3619ab
    .dword 0xa9151e084124bc2e, 0x54dd980e018c272a
    .dword 0x16d0e233f0e0e56c, 0xbd191bab6ab9571c
    .dword 0x7172eca87bec2da6, 0xaf946f46933dec97
    .dword 0xb91aad8f454d112a, 0x3e759ccd5afc646f
    .dword 0x9ffefff1de793bbb, 0x3cb52346f277cd13
    .dword 0xf78f12af1614e4b3, 0x7f380f5fb5e4b066
    .dword 0x58f76ef8ec07527b, 0xd4c408fc7784a6a6
    .dword 0xda8e0354147dae40, 0x80589cc95beed5d0
    .dword 0xe2d96d656a20d19, 0x674bc718e6d88579
    .dword 0xaa9f29bc28ecb435, 0x3999a6815eec0a8a
    .dword 0x9f0cabc02baa5f59, 0x67b4eb8076843478
    .dword 0x77ddd96703e8bbf9, 0x15b654ad6bbf7a0e
    .dword 0x17aaed533e45cdd5, 0xd0c18c48c4467c19
    .dword 0x429bd7847fcd81b, 0x90eef1c4bde5fda8
    .dword 0xe1d7f934b7d1a4e6, 0x895a9c9d32861b1c
    .dword 0x6d67e71b942aa75d, 0x7cc043a88d1b059c
    .dword 0xc3d93a191d3a7dac, 0x3fd1fc99f3982589
    .dword 0x47c9fa721bfa5b42, 0xfa11f0afedda0920
    .dword 0xf6f5eb0970a153f9, 0x54c4f2f1d81029e6
    .dword 0xd507a4b7da6770f3, 0xf485ed338516cebb
    .dword 0x1921de963e123ef1, 0x9466c424b65139cb
    .dword 0xb9d63830fc9c49fb, 0xb4d11144fed959f2
    .dword 0x75f08c4f849c0534, 0x2a60a6c9c0cbfce6
    .dword 0x2291cdb2e7728e4a, 0x46615bff62737da5
    .dword 0x58e513646de67159, 0x2fdd1dbce4654d8b
    .dword 0xb6267b1399703a85, 0x968eba02d05beaab
    .dword 0x167e354890c20135, 0x37d88eed4a1e19b3
    .dword 0xc3f1ff707b73a021, 0xc058b96923b38a
    .dword 0xdbc79a90b3b7e423, 0xde57fedeca230e12

    .align 12
data2:
    .dword 0x40e8f6a73213fd2d, 0x69800258ffd1d025
    .dword 0xf65224cd921a78aa, 0x2af036ac58abd9d8
    .dword 0xaa19b6b1b9bb2643, 0x4ed58a79404f0bda
    .dword 0x3cd290315c6ea88f, 0x99695de14c1124ee
    .dword 0x17b227c44460bf75, 0x37a5893bb7ca2712
    .dword 0x758e536bb4ba0cbf, 0x3f5e90f6d88cd257
    .dword 0xfc215bfc52141276, 0x789ecf0244e0eb87
    .dword 0xf67a1496e3545fc9, 0x59f117ae32ef1f62
    .dword 0xfd193ff4c2eb290b, 0x2f3f673b7358828e
    .dword 0x20ba21e06f311494, 0x595fd9fbf5096e6e
    .dword 0x7a79d24eb1ae110e, 0x98299a5877859038
    .dword 0x32919dd9d2bdd008, 0x625ad4004c4d8a89
    .dword 0xd8b3be4d5bf94414, 0xf943cecf408b2eab
    .dword 0xdf5ed69dba07d983, 0x876a770ed86da792
    .dword 0xf999099707c537e8, 0x48113284e98d941c
    .dword 0x60241f213a16555b, 0x7066577e0cc503ff
    .dword 0x99f1bb3cffde34a4, 0xa2620a9fddc116e7
    .dword 0x7669cd56013e6295, 0x1180093139085088
    .dword 0xa76133f0319e60b5, 0x8371b7036d97560
    .dword 0xeb5280e7e30c0bee, 0x91c02304860a7cc0
    .dword 0x1b914c1ef9dd2716, 0xec14f6b8515f1caa
    .dword 0x3879cbd102ae25f1, 0x8cbf7992e5c8902d
    .dword 0xdea6db8c4461c456, 0x87fb18bb2afb12f9
    .dword 0x7ae7de1fd5730cd1, 0x3a6e3f9b05d283a
    .dword 0xd8a1824da4486841, 0xa575e1b29eef6970
    .dword 0x19ada325a07acb1d, 0xe33a1262e5e46895
    .dword 0x5bc9b2af39d3eec, 0x483806e0aed04587
    .dword 0x96c0e38beaa63a39, 0xe9c6f7b6b5a6ec02
    .dword 0x4d940b796f89dd9e, 0xa21f60b03339afe1
    .dword 0x6de36ebc1325889f, 0xe20d1f08b0bf4c1
    .dword 0xdad8b0c53f65f865, 0x4b8eca77a6eb013e
    .dword 0xa7449415999241ce, 0x5acfac25c4ba5dcd
    .dword 0x38cf202f532ec7d8, 0x93c2a7a0baae6564
    .dword 0xf2514183ec3e2f8b, 0x483bd6e96ebf02fa
    .dword 0x35bed9fe804b5a12, 0x2660dddc767116d5
    .dword 0xb26d6ad5a46e5a44, 0xe4dc709ec4efa5f7
    .dword 0x5524c88f7b5cd3dc, 0x24d57ca3300908c0
    .dword 0x9324bd6c7df239f3, 0xbef80f2d3c0f9ee5
    .dword 0xf85d962dda20e6f3, 0xd42f4bca6e4e4267
    .dword 0x2efb78a3b79153f7, 0xb80ef1d4b731361
    .dword 0x56395faae9004186, 0x1af202c36cc1589d
    .dword 0x265bd7ffdef40337, 0xc7ee9eeaccbaadfa
    .dword 0x16b9cdd67785ec1, 0xea25f85203543f72
    .dword 0x2ff3166ebe982de3, 0x6f1fe6e23a342b1d
    .dword 0x5ca57137f155e117, 0xeb24a9d67493f1a0
    .dword 0x401582bdb7419e07, 0xc00734166b006736
    .dword 0x95598164670dbc83, 0xf278c134c58b988e
    .dword 0x8c6f490fe88ef2a3, 0xe50542e5a7df29c9
    .dword 0xfd51bbc4536e1ad9, 0x3651dce89564b4
    .dword 0xad8ddb8dccd44c91, 0x87ed6a4b1060ab12
    .dword 0x880bf06463d4a02e, 0xa51bccc2bf5e3710
    .dword 0xef8a7259544e4bb, 0x2dcc260e57a3687b
    .dword 0x250d7dc6beff70cb, 0xc8e8108491d5e281
    .dword 0x7e33110709fdfda1, 0x5da461d329c6517e
    .dword 0x3fe77717ec044b62, 0x5cff071509659b3f
    .dword 0x3be08f76481e5a3b, 0xc9b473043095c5e8
    .dword 0xc0a402cda4e5a6e5, 0x3b02c113b5dc9b13
    .dword 0x826c3c4a2e96fed0, 0x4b74337b9bd3902a
    .dword 0x8b28c0b8c1ae3c3d, 0x5d2fedac6f8f9d34
    .dword 0x6bd60de118655, 0x9349aee3e828538e
    .dword 0x8115f5fd679d8c99, 0xe9c0d0786660f433
    .dword 0x18166fbde5869da, 0x4604df4e09bb642e
    .dword 0xfb5b839bbbe06223, 0x493281b6a2e4b19c
    .dword 0xdcd5c5031181d2e1, 0x9ae75e7f505b03eb

    .align 12
data3:
    .dword 0x8c5b6bbfed44cbcc, 0xe937c5eb6ce9edc3
    .dword 0x65c53fc0ac627f7e, 0x79f89da73fcebc16
    .dword 0xcb67029ca9105215, 0xe701d392bbcf363
    .dword 0x1c43c71727a21745, 0xf2d82d77a58304ff
    .dword 0xd4b58bf5be2af898, 0xc2e1f305625c6a3a
    .dword 0x5fafe263743fc81f, 0xd76ce84d83261c2b
    .dword 0x75712515f0623547, 0xf2609a3969f39ba7
    .dword 0x69ce3acdf42b4590, 0x31fde980a2bcaa03
    .dword 0x79cbb5992b70f75e, 0x70c1cea5002aa247
    .dword 0x58bfdc8c9e97d2a5, 0xad3b36a89d6244d
    .dword 0xe8030f16f55450e3, 0x5f5344b97b217bd6
    .dword 0xafee4380ce9d17dd, 0xd8dd662a311b1868
    .dword 0x7fa6c82090c62361, 0x91a94a801f5a592
    .dword 0xeba5b58abdf6266b, 0xdacd3281244c9adb
    .dword 0x5dc132786de5605e, 0x1dd4c65c532764ce
    .dword 0x7e2d4b8f1df5210b, 0x9381400d20bdf42e
    .dword 0xa6ea2824b93d396, 0xa82d26f7fe3ff96a
    .dword 0x645dd7454a7fa473, 0x7c2ddd44a3151c86
    .dword 0xb5534e3fbd440c6f, 0xd2f8c8b12ee3d7a2
    .dword 0x8ef511eedadcab61, 0x43d489517168c0c2
    .dword 0x8ba2e1bba5971722, 0x5f2fb5da31c5f452
    .dword 0x5cee1ea94ee65a2a, 0x9c4b5e8afeacea93
    .dword 0x8dce5a188638fd50, 0xa9c31f3921dc30ec
    .dword 0xf6003515220322b2, 0x46c0dbab35f88850
    .dword 0x49a71e4f69ec489b, 0x5a625bde1252f163
    .dword 0x4441dedd01bca97f, 0x511b432b491cebe
    .dword 0x48dd4d4110a5ac39, 0xed8b78a9ac6ef837
    .dword 0x3c6692cca3b90920, 0xe2d888986ef0119c
    .dword 0xc237eb4da526e2c2, 0xedd0d1e03d61237a
    .dword 0x3856ad6d8fad5db6, 0x6e9aea0c2cdde35d
    .dword 0xf657af074cd877e3, 0x3be2fb5375f17f33
    .dword 0xc3fb1e7e31396353, 0x7d2da4075786548
    .dword 0x6c5f883f5e8758fb, 0xdb9559b2914c7f80
    .dword 0x20e2d6390ff81512, 0x272206040095b38e
    .dword 0x5c8f476f50724bc8, 0x8ef805edf4d2ed97
    .dword 0xffbade9033e9af1, 0x8b2a89f0c06321b7
    .dword 0xa28658b93d6ca096, 0xd9ff1f590e4dd97f
    .dword 0x241ddcae3362d206, 0x666bbc48afa7b831
    .dword 0xaf5f3d3ab377ca55, 0xc5ce4ca48c6e57c3
    .dword 0xc3fe2cd39691cec2, 0x76f64d4e586b34bc
    .dword 0x688c56b660abe7a6, 0xb709bfbf991c5d09
    .dword 0xdafbd707206470d1, 0x9293f5cf5d67ee4
    .dword 0x1f226cc34e7f9109, 0xd7a427962f560d7e
    .dword 0x8fce216738ebf58, 0x843a4c18c50d20b3
    .dword 0x52df241dfbc9051, 0xb34301debc1b5e1e
    .dword 0xa618b8d92f1fc73, 0xe554eca76f6158eb
    .dword 0x412c9284cd8e4cb9, 0x11767f78404e4563
    .dword 0xe2f79ad376ee4430, 0x6196bdcd06a51f19
    .dword 0x78f5e9b91959fd84, 0x680cf30cec479a50
    .dword 0x729146c9f133d92a, 0xddb52bc1b40f2878
    .dword 0x2f0e1cf249cfdaee, 0xcf0440345f3bf2e3
    .dword 0x93ac6a2ce4a36331, 0x489b90a5d50093ee
    .dword 0x50169ab9de9461fb, 0xf0b9564e7dccb358
    .dword 0x389c0669ae9ed2c1, 0xf26e52c86c1ab5c8
    .dword 0xae81183f19dd9c53, 0xb0abf0ae729699a8
    .dword 0xc188fc4dea2bc0b, 0x25c453b47269699
    .dword 0x2f57490d3e637340, 0xacfb4d8d7c947223
    .dword 0x7c80e4263aae128f, 0x68a563ab0d049629
    .dword 0x74df7a8e15b821d5, 0xbfce2528e1e842ed
    .dword 0xd2742b5beed268c0, 0xaabc0ba4f46721dc
    .dword 0x2d40c1ed15178843, 0x404eeb44fdf7947c
    .dword 0xdb8a71e76486d958, 0x94ce10f6f978a811
    .dword 0xdf0417427ce7ea3d, 0x9fb54c98ec07ca6
    .dword 0xfa30ee1f5920b608, 0x47ee2b79551e6f61

    .align 12
data4:
    .dword 0xf1235546c3cff900, 0x74268fdd493b70d0
    .dword 0x50501ef5651cb5bd, 0xd548ef663f4d4582
    .dword 0x6a5a69f727b03074, 0x3facd7423e101361
    .dword 0xc57f5a7f2d8138fb, 0x4bfe822f93e91c29
    .dword 0x3ad312a6e2fd7a86, 0xe24ee4e4d45c68bd
    .dword 0x7ca49d32f45e99b4, 0x15465f475ee0fe4
    .dword 0x2c6aa885366db71b, 0x1661749063a5726
    .dword 0x94634976ab3e67a1, 0xe0666be7893960ed
    .dword 0x91b358659e7394a2, 0x43640618c1fad13a
    .dword 0xf35d94e1bdb0ecf0, 0xca813f3b6fb0d191
    .dword 0x6b981bdea6018f63, 0x5ff988fd11fb0f0
    .dword 0x450a68e522130043, 0xddf41229f5bcf21
    .dword 0xbaaf44158a79b966, 0x829d234c13049cef
    .dword 0x91accf6d8a0911c5, 0x3cdfd970b7f7d51d
    .dword 0x3a453cc426d8c0d7, 0xde1f87bf01dcab4e
    .dword 0xa7cbb4d49122df2e, 0xceb7c7a7bd0a2446
    .dword 0x5c86a49066d94eeb, 0x7f039e58e1f3f536
    .dword 0xe2efca0d5745a43a, 0x358368ef70006311
    .dword 0x741ad9f66182d15a, 0x7b0a49caabe4d362
    .dword 0xac6c236bbab35724, 0x395af8689e355b62
    .dword 0xd50c421c417815d9, 0xea3a3f6e097a63d1
    .dword 0xf1165253d25f785e, 0x78e57243fbaf2b86
    .dword 0xccfe5b70bfc279a6, 0xe365dc4cdffd6499
    .dword 0xcf578c9aa0266044, 0x528689bfbb8b2b14
    .dword 0x8127fae7f5d03b04, 0x79370f4e765ab964
    .dword 0xc2f685ca3553337b, 0xb205799210b68ddf
    .dword 0x53325350d5ad5e2, 0x1a24f568f9d266aa
    .dword 0x60d8a4fe9c9417c3, 0xbf8067b307054868
    .dword 0x4ace52fbe6dbd8a3, 0xdf05e5cc00afb1f9
    .dword 0x33ee8cdd2c2b11b7, 0x18b77910c449e2a9
    .dword 0x38f79733d046e001, 0x25a3bf3b93de9dad
    .dword 0xb4470741a3f7fc11, 0x923678d1f3a318c4
    .dword 0x5696ed2eb9a2f68e, 0x1f03de4504204504
    .dword 0x3cd6ddfa3e73140b, 0x71a182e910292b54
    .dword 0xe6e825f8defe369b, 0x70c81559e6b2bdff
    .dword 0x89efd5f58c9e3fd, 0x5781d559a72c085f
    .dword 0xf643f8332d82ec91, 0x8bd2ce9e5971c692
    .dword 0x325393b60a62c041, 0xf5bd18b274a5bd63
    .dword 0x5246e914ab350a3d, 0x8a53f2a97d528783
    .dword 0x85a3eee6651c4844, 0xf424a990d414c210
    .dword 0xbd83578b7115a300, 0x2a3f7005d1065ecc
    .dword 0x6372bc6097c0ebea, 0xa9393bbf80f9e6bb
    .dword 0x9882151599397735, 0x374b2446310b1752
    .dword 0xba1e733a2115c7b, 0x2eee249baa9313f0
    .dword 0x4c4d4da28c3879db, 0x29134756401b2fc5
    .dword 0x7264bcfed6131adb, 0xf6116c7e1e79ffec
    .dword 0x9a180af42f52b599, 0xa926117787561513
    .dword 0x6dc201f659baac7d, 0x3d936ab08fb17ee8
    .dword 0x715c4f43ec43e3d5, 0x8282d80b82125022
    .dword 0xf6b3711d9142cb90, 0xc654c77feedcb40
    .dword 0xb45547524d6b4fb4, 0xb0223fa2cc534f2d
    .dword 0x41e70410bb7cae9c, 0xf2d1e4a55980d7d8
    .dword 0xb72bf51e30dae8ad, 0x3111f6237c2f23c9
    .dword 0x20a99755988c7971, 0xf2526c9efe405d20
    .dword 0xfea09ac43c64ebd7, 0x5ae49f44747c4146
    .dword 0x9f36201f2ab0a0b0, 0x30e6b8cff055eb0d
    .dword 0xb5d33829753b393f, 0x5671ac90e5835c68
    .dword 0x77830b455b5f96bd, 0xf531c90a0436824
    .dword 0x741c0814393b5fc, 0x6a888ea060e2543a
    .dword 0xca7d041f6ee9ad6e, 0xab233b56636ed08b
    .dword 0x75b0c4febbabfb27, 0x1007d8c96bdcb67b
    .dword 0x29ccbefe65b97c7d, 0x52c06e5d28ce5bb2
    .dword 0x1b1df1a959878303, 0x7310ed5dbe1e84e6
    .dword 0x2f545a60b805211f, 0xba891602c7e7a52f

    .align 12
data5:
    .dword 0xdb474b3934705e65, 0xd28ceb18f112290d
    .dword 0x325a51758eb9839c, 0xe427171737bfa9a6
    .dword 0x654527e7bf4af7f7, 0x6fd5de6424782396
    .dword 0x228ca64246cece43, 0x64ede8f61acac2dc
    .dword 0xe7777f62374148e6, 0x66a342d4cc9c872c
    .dword 0x42ae6f5d45908a19, 0x2a67403d10a6ac85
    .dword 0x7cd974444a2ae688, 0x1f362fbd897dced7
    .dword 0x14c9b955b2cf0e0b, 0xa8458545ce43b146
    .dword 0xf3524095fb416e6b, 0xdb1e339962398f5d
    .dword 0x9515bd17051007d6, 0xa1e495bc1c39f136
    .dword 0xa5800bce2f4f8065, 0x7da2021cf270b8e3
    .dword 0x730ab6a78f1364c7, 0x258c105cca38389f
    .dword 0x95ef4ce9ae0143ee, 0x5213e9788def786
    .dword 0x25aabcf240dfef9f, 0xac3619f154385064
    .dword 0x2db50217690d7f26, 0xe64bc511bcf48567
    .dword 0xf379e65f7e11fa34, 0x746f13b10d831ca8
    .dword 0x3e5fc8cb13d72a3f, 0x865790e97ab2b390
    .dword 0x83e60afe644fb940, 0xfa78cd59d0bf122e
    .dword 0x38842aab21e6dcad, 0x65805e611dea2e34
    .dword 0x3b124136f8892a95, 0x71837c1d07a0af44
    .dword 0x893d18d3198cbeb0, 0xe79d85db6bbee3f7
    .dword 0x4495458c3865f40a, 0x75e9af200d610beb
    .dword 0x1f8520924eef778e, 0x5a48f853cc0162db
    .dword 0x25edbb753692dac5, 0x988aa37e69aa1696
    .dword 0x8bed5a47c6c0aa0f, 0x48feeddbab8a4e5f
    .dword 0x332b661f378a5e2a, 0xb4cc0f65435db41a
    .dword 0x8f0dd1bbb7839d35, 0x9863be39a9d5cdb6
    .dword 0x95311583ee8c878, 0x468741cc0b4d4753
    .dword 0x97097a7de0585b10, 0x202b16fdbe4bfae8
    .dword 0x58cc71201d41c4c6, 0x92c292d7be68c923
    .dword 0xf41cbe197d0e3b28, 0x71e5917d46495cfe
    .dword 0x63e9862ec448a7af, 0x68fafbb94e169a1b
    .dword 0xf31bd83e2f582458, 0x6aaf9946949d2ece
    .dword 0x64266e49c807769b, 0x3d2f0944f0851da8
    .dword 0x58d236daec76b731, 0x4fa35fde4b8d70e
    .dword 0x251f0d4e0f048938, 0x4fa4a4250d00f63e
    .dword 0x468d20ffddf1a95f, 0xa8f1046917831c9a
    .dword 0x1a9824be421cbe65, 0x41eafbabbda42ff7
    .dword 0xb0ceae1a090a5971, 0xe0caef03067ee8f9
    .dword 0x1d461b33d9a67223, 0x2f4802555edcfc6
    .dword 0x6cd0952dc27fa747, 0x7371de4bd6cbc02d
    .dword 0x31f95ec57a3da8fe, 0xe819547fdec6eab0
    .dword 0x9b1e220e3e287f43, 0xfc3bed95f156b4bd
    .dword 0xc968a9c4778f78b5, 0xf6ed794c8976b207
    .dword 0xbdac3e3175d8a593, 0xbb0341786562f90d
    .dword 0xc4e495baecc8b13a, 0x43c1983ef2137524
    .dword 0xfdb556518f9042e6, 0xbf5a332c02065d45
    .dword 0x1b65b3f38d31a16b, 0x90aa88dbbfb9601e
    .dword 0x54f17d1817b0d854, 0xacd6f8bed566d766
    .dword 0xe39e4102a06d5871, 0xd31f9282a4dfaed3
    .dword 0x64efbc98a57375db, 0xa40a0d7e6252cb7
    .dword 0x336aacf3e398eab8, 0x721c63b9819130ff
    .dword 0x64aec64cb1c8f58, 0x1c8413819d3febb8
    .dword 0xcc69d9db3877ba7e, 0x229e08b8cb0a4df2
    .dword 0x41549ae6334067a0, 0x730e1c8f828ca030
    .dword 0xcd71a248c659d409, 0xb8b58b52731fbdb
    .dword 0xba36034f1fa899ab, 0x1e6ebeeb969334d3
    .dword 0x80271138a8ecaa0d, 0x28ddae9bad17ba0a
    .dword 0x938d222593353a09, 0x9cf045a43ff3d67f
    .dword 0xf9a9a2009720a83, 0xa5b68164ecad8e7b
    .dword 0xae3e84818d39b34d, 0x3734b8058e1a554b
    .dword 0xc1dfd1ea8b5d3c2f, 0xc8f08246e17c7d18
    .dword 0x6e6bd8408c25a12f, 0xa8b62f0359608675
    .dword 0xffdce63d511c129d, 0xf2d91eabfa0d465a

    .align 12
data6:
    .dword 0x3565173c94f9ae10, 0xef732404542edf29
    .dword 0x17827e6da9f8a550, 0x8bd846a16383789c
    .dword 0xc878b0b5e7b31a4, 0x2df9749b1a72350a
    .dword 0x257c24a79b69464, 0xb9f50b0fa35e8e8
    .dword 0xb3cb2a5891e57c72, 0x82d0d047a9513b23
    .dword 0x2606775009235790, 0x85d29e978f47adc0
    .dword 0x6d2942fdc7788be8, 0xb2fcc08853f2d7fd
    .dword 0x347e5ae990dc6330, 0x5cce23be49671dd8
    .dword 0xa91cd7ef73038410, 0xb438f6decc5facb6
    .dword 0xd0e840671aa2cf8b, 0x3e40796ed7dbe01d
    .dword 0xf48936ac8288bf82, 0xde36ce0f8f64ec13
    .dword 0xbee43b09ed1307e6, 0x3977905a405cc414
    .dword 0xe41b927ddf65b702, 0x5c56270c2476b8bf
    .dword 0x55a1455e1126f8b, 0x7248920164cf42fe
    .dword 0xb16eb2a10674f2df, 0x14502615c2804afe
    .dword 0xcb252d9c99e0930c, 0x7fc5ec16142881db
    .dword 0x5d9f0346c8ded9da, 0x50141e90c4829482
    .dword 0x5cf34995f2cba86b, 0xc1037c2829945802
    .dword 0xea4b086240143d9e, 0x48540dce647240be
    .dword 0x9f03b2267e461232, 0xb636b42ad1ef369f
    .dword 0xdc77bdc510ce57c4, 0x2fef8d1c3b65818d
    .dword 0x778ebfbabed2e16, 0x37ba858b9a5cc5ac
    .dword 0x4263ff4e2aa3fdc5, 0xd1c6dca147ba78e4
    .dword 0x5734273e6585aa3b, 0x13541995a11f0d1d
    .dword 0xd63606cb219f6230, 0x982d66c38624b8bb
    .dword 0x505023847f28981a, 0x76d8492654b98b65
    .dword 0x7ffc3c69760394d0, 0xca4cbf013237e4bd
    .dword 0xaae422a56fbc14e3, 0xfc927cdbfb86f89d
    .dword 0x7bb363510aa72095, 0x80642d98c6379d01
    .dword 0x133b79f28e29e1d2, 0xdd71907aab3a6df2
    .dword 0xafb152c4055eb648, 0xd1157f4a696c030
    .dword 0xf19e0bacc19459ec, 0x5abde7760de5c153
    .dword 0x78bf277c1ef7253a, 0x8f20d02e3333f903
    .dword 0x97e4d8a46a899107, 0xbd327559ce8ffaf1
    .dword 0xd1d3547f897c2c16, 0x58199f40d8aa4f64
    .dword 0xb49465646a4eb8d4, 0x65df076ef29a0354
    .dword 0xcecdcd97270c2d0c, 0x963c59b76f3b2fcb
    .dword 0x429d2bcd8d360047, 0x24d18d4c7e4dd469
    .dword 0x4bba26aedeec5699, 0x83cfe399e9a441a7
    .dword 0x7533ecee1919f12, 0x67e88006956d3132
    .dword 0x17be26ae4d9a1374, 0x81504989b4e5d7f
    .dword 0x970f133c7f441d8b, 0x657466a638434985
    .dword 0x5ccdbda1fd9a42a7, 0x295ab734ae7fac28
    .dword 0x2d9d5d82d6e140b, 0x5396cd8b74e2bcc8
    .dword 0x3f01b0969e993e49, 0x7616f348430f0b3
    .dword 0xa819a636c9ede2f1, 0x497833658a5a8ded
    .dword 0x3113287bd2307f84, 0x6dcb71ba2bb9d194
    .dword 0xe84e434320f8223f, 0x329b610f5ddb05d
    .dword 0x5af4fc5bff40670, 0xb06a56d38dd0f55e
    .dword 0x43ea08c6ea73decb, 0x5928af0d841a1138
    .dword 0xa27e704602487c98, 0x9fb0d4176add5b1a
    .dword 0xca916ce17298eda6, 0x6f5b8c889eb0b45a
    .dword 0x941e35edbc94ce83, 0xef41b79f6a6032c7
    .dword 0x86a6c44b1f48d0e5, 0x801e202ff850af0a
    .dword 0x9bef24fec637e953, 0xcc8a90a94bed60ca
    .dword 0x5df7743b4f64ea16, 0x51ff6709011e628d
    .dword 0xef8c70cd8b38c79e, 0x78bd1ff3db57e374
    .dword 0x47c22b274d19504f, 0x5151fee5d57c90d2
    .dword 0x6b8473bebe2de715, 0x9c9ee0dcab2171dd
    .dword 0xb786501e855616a2, 0xb5b2dd6912f8f46a
    .dword 0x85a62619614c26c1, 0x970be1742f575029
    .dword 0x917c1fe6e9bd53dc, 0x5db93a30675868cf
    .dword 0xcc7a6171e3cc4711, 0xf4ccef05cf7b5a66
    .dword 0x53ae0cd3879c9be4, 0x344b43c2f924fe31

    .align 12
data7:
    .dword 0xd4797215fe574316, 0x459f98abe31f403
    .dword 0xf7eedc0607414af9, 0xe32ad3d1070ddc60
    .dword 0x972dc497c782f1a8, 0x6c321f7d0eb22859
    .dword 0x960fee45d40b079a, 0x8eca0003a3da9884
    .dword 0xd859451f3b727c08, 0x7d5287036d44067b
    .dword 0x2c410072656fe1aa, 0xe5a0c161b34283e1
    .dword 0x93e55bff62c46e14, 0xa8d29eb2f3431737
    .dword 0xa5bd6f6cd8173659, 0xe88743616a9ac259
    .dword 0xf447a037ec2ded2b, 0xe02ca419b59e8cfc
    .dword 0x631788a97407e3e6, 0x929ae0f0494ba8ab
    .dword 0x9396fbc24efd7ca8, 0xd52e498cf19e0803
    .dword 0xf4121bb89ecc5afd, 0x534c68bfcc151310
    .dword 0xe9bc32c2ebf8d012, 0x54746d1d746b6c7b
    .dword 0xe3cf4defd3010e77, 0x6dc993e561fa2c5
    .dword 0x2cb2a678f048379b, 0xb49daf461055e4b9
    .dword 0x862a918dccbff389, 0x8d76ee2e3d92c310
    .dword 0x9c87e84b1a8a9bce, 0x4d9e3924e780e5f
    .dword 0xa4cf150ddc5e3b39, 0xea47c22979ab8fe
    .dword 0x821ce23dc338a3d7, 0x2a2594ebab12c94a
    .dword 0xc93fb4bab17cfd14, 0x6e1e2dc32985ed7a
    .dword 0xac0eb8c6824535f0, 0xc18fe5e97475e92
    .dword 0xa0d47f76db89de10, 0x6d08b2508d3e77ef
    .dword 0x550b54ac3aa63730, 0x2882fe938f1a899c
    .dword 0xe96d47841e6bf70c, 0x9834d2e4c0f33655
    .dword 0x9979aad8011ba6dc, 0x93693238f603279c
    .dword 0x2265f7993c7d19cc, 0x86d50fc8a95ecf60
    .dword 0x18d5ba95d20d7559, 0x5e077d6445273d2
    .dword 0xbb2e63b12482d223, 0xe09a3aae8be1e9ec
    .dword 0x6d67a01fb0a5c729, 0x842c97e83af96d83
    .dword 0x53f7d0bc034a3848, 0xd11da323b0aa2589
    .dword 0x9fedda1c64fbe2f5, 0x53b6e1a4ce538639
    .dword 0x4b2ec5d92d20c00c, 0x4e9d5ebc1811a158
    .dword 0x95f18a1814fd85fe, 0x9da859c98fe939df
    .dword 0x4142c4c093cad8f0, 0x96710b66f28a1925
    .dword 0x3330e739e5d66971, 0xe381d8b652fa16a
    .dword 0x4db70138333b1399, 0xf637c57210a0a49b
    .dword 0x89ebe439a00a6a7e, 0x85bd305620218b93
    .dword 0x1a92d11797ace2a7, 0xfde9575a9c691f31
    .dword 0xe9a28f4e8c6fb9ac, 0xcb7dab87381a64ad
    .dword 0x9e40fb7ab4482b21, 0xc8d2c3db8db25ac9
    .dword 0x38fcc5bfedbb365a, 0xecbffe2321dc63ce
    .dword 0x1d74dc41173e6cf6, 0xd044dad5271b205b
    .dword 0x2296eb25330d3de7, 0xafbf027cedae432d
    .dword 0xd0a2df3f2769fe1d, 0xc691bd62b8a4c1ef
    .dword 0x4638a4a97f7f9bf2, 0x54e27204ef2dfbf2
    .dword 0x1e6f73afe337f658, 0x77bf82e193f80508
    .dword 0xbe91ae4f64e5903, 0x3531bda8db5669b5
    .dword 0xe55c0dde20df3c7, 0x30268566105600af
    .dword 0x865a0deaeaebb8da, 0x5f2caeda58614239
    .dword 0x28bd887e6288af79, 0x86fd27290561d770
    .dword 0xf084ff648a1d03aa, 0xfac53746c154be2
    .dword 0x3808bcf0cf340fee, 0x2c28c119e60926eb
    .dword 0xb37da0e5d9c3f3ba, 0x8b9ac81ed4dd4397
    .dword 0xf24180bd76923093, 0x20bed1a8b6e2bd73
    .dword 0xe67206e08da055ba, 0x63c7ea35ea67cb9e
    .dword 0x6514d73026d4e7ef, 0xc34b32b47721f2fb
    .dword 0x16b15276ee05c251, 0x17cca7b2498f3395
    .dword 0xb22062c4224a3e3e, 0x128bdbe256389723
    .dword 0xa92da5b5ac3edbfe, 0xe779e8534ce0a4f4
    .dword 0x211ceb4be30488ac, 0x608a9f5067e9453a
    .dword 0xff497033839821b7, 0xf72cb6f8816c6de0
    .dword 0xb70e02329a16472b, 0xbf94f89aa33c77cd
    .dword 0x5faf6fba9efe6db9, 0xba164d09a20b305b
    .dword 0xd8c66f1952334671, 0x36d99a6b7e507993


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x0000000000000000, 0x0000000000000000
