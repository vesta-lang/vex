/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/env_flags_table.h
 * @brief LA lista de mandos del entorno.  Sin cabecera de guarda: se incluye a
 *        proposito varias veces, cada una expandiendo la macro de otra forma.
 *
 * Una sola fuente para el enum, la tabla de descriptores y las huellas.  Con
 * dos listas separadas, anadir un mando en una y olvidarlo en la otra no da
 * error de compilacion: da una huella que no lo mira, y entonces la cache
 * sirve codigo compilado con otra configuracion SIN que nadie se entere.  Aqui
 * eso no se puede escribir.
 *
 *     VESTA_ENV_FLAG(id, nombre, alcance, dominio, tipo, so)
 *
 * @param id       Identificador del enum (@c FlagId::id).
 * @param nombre   La variable de entorno, tal cual se lee.
 * @param alcance  QUE cambia al tocarlo.  Decide si entra en una huella:
 *                 - @c Emitted   cambia el artefacto -> ENTRA.
 *                 - @c Speed     cambia COMO se hace el trabajo, no el
 *                                resultado (reparto por hilos) -> NO entra.
 *                                Que no entre es una AFIRMACION, y la sostiene
 *                                `tests/vx/incremental_identity_test.py`: si un
 *                                dia cambiara la salida, ese test lo dice.
 *                 - @c Report    solo imprime o mide -> NO entra.  Meterlo
 *                                seria invalidar la cache entera por pedir
 *                                tiempos.
 *                 - @c Runtime   cambia la EJECUCION, no lo compilado.
 *                 - @c Location  rutas (donde estan las cosas, no que son).
 *                 - @c System    del sistema operativo, no nuestro.
 * @param dominio  A QUE parte afecta.  Es la granularidad de la invalidacion:
 *                 tocar un mando del JIT no tiene por que tirar lo que se
 *                 guardo del optimizador.  Cuanto mas fino, menos hay que
 *                 rehacer.
 * @param tipo     @c Bool (APAGADO por defecto; lo enciende cualquier valor que
 *                 no sea "0"), @c BoolOn (ENCENDIDO por defecto; solo "0" lo
 *                 apaga), @c Int o @c Text.  El defecto va aqui y no en el
 *                 sitio que lee: en el codigo habia las dos convenciones
 *                 mezcladas y desde fuera no habia forma de saber cual era
 *                 cual.
 * @param so       En que sistemas EXISTE.  Los nuestros son @c Any: los
 *                 definimos nosotros.  Los del sistema no lo son, y decirlo
 *                 importa -- `APPDATA`, `USERPROFILE`, `TEMP`, `PATHEXT` y
 *                 `SystemRoot` son de Windows, `HOME` es de POSIX, y solo
 *                 `PATH` esta en los dos.  Sin este campo la tabla afirmaba que
 *                 todos existen en todas partes.
 */

/* -- Optimizador de IR: nucleo ------------------------------------------- */
VESTA_ENV_FLAG(NoFuse, "VESTA_NO_FUSE", Emitted, Optimizer, Bool, Any)
VESTA_ENV_FLAG(NoCmpJmp, "VESTA_NO_CMPJMP", Emitted, Optimizer, Bool, Any)
VESTA_ENV_FLAG(NoCarryIdiom, "VESTA_NO_CARRY_IDIOM", Emitted, Optimizer, Bool,
               Any)
VESTA_ENV_FLAG(NoIrCoalesce, "VESTA_NO_IR_COALESCE", Emitted, Optimizer, Bool,
               Any)
VESTA_ENV_FLAG(DceEffects, "VESTA_DCE_EFFECTS", Emitted, Optimizer, BoolOn, Any)
VESTA_ENV_FLAG(NoStrengthReduce, "VESTA_NO_SR", Emitted, Optimizer, Bool, Any)
VESTA_ENV_FLAG(NoMbInline, "VESTA_NO_MB_INLINE", Emitted, Optimizer, Bool, Any)
VESTA_ENV_FLAG(NoSpecDevirt, "VESTA_NO_SPEC_DEVIRT", Emitted, Optimizer, Bool,
               Any)
VESTA_ENV_FLAG(ModuleInitChunk, "VESTA_MODULE_INIT_CHUNK", Emitted, Optimizer,
               Int, Any)
VESTA_ENV_FLAG(TreeShake, "VX_TREE_SHAKE", Emitted, Optimizer, Bool, Any)

/* -- Rangos de valor ------------------------------------------------------ */
VESTA_ENV_FLAG(NoRangeCache, "VESTA_NO_RANGE_CACHE", Emitted, Range, Bool, Any)
VESTA_ENV_FLAG(RangeKeepFloor, "VESTA_RANGE_KEEP_FLOOR", Emitted, Range, Bool,
               Any)
VESTA_ENV_FLAG(RangeStats, "VESTA_RANGE_STATS", Report, Range, Bool, Any)

/* -- Desambiguacion de memoria (alias / points-to) y sus consumidores ----- */
VESTA_ENV_FLAG(DseUnified, "VESTA_DSE_UNIFIED", Emitted, Alias, BoolOn, Any)
VESTA_ENV_FLAG(DsePureCalls, "VESTA_DSE_PURE_CALLS", Emitted, Alias, Bool, Any)
VESTA_ENV_FLAG(LoadCse, "VESTA_LOAD_CSE", Emitted, Alias, Bool, Any)
VESTA_ENV_FLAG(LicmAlias, "VESTA_LICM_ALIAS", Emitted, Alias, Bool, Any)
VESTA_ENV_FLAG(SchedAlias, "VESTA_SCHED_ALIAS", Emitted, Alias, BoolOn, Any)

/* -- Escape analysis y promocion de reservas ------------------------------ */
VESTA_ENV_FLAG(NoEscapeScalar, "VESTA_NO_ESCAPE_SCALAR", Emitted, Escape, Bool,
               Any)
VESTA_ENV_FLAG(NoEscapeMem2Reg, "VESTA_NO_ESCAPE_MEM2REG", Emitted, Escape,
               Bool, Any)
VESTA_ENV_FLAG(EscapeMem2RegForce, "VESTA_ESCAPE_MEM2REG_FORCE", Emitted,
               Escape, Bool, Any)
VESTA_ENV_FLAG(NoSroaStack, "VESTA_NO_SROA_STACK", Emitted, Escape, Bool, Any)
VESTA_ENV_FLAG(NoDeadStackSlot, "VESTA_NO_DEAD_STACK_SLOT", Emitted, Escape,
               Bool, Any)
VESTA_ENV_FLAG(NoPromoteLocalAllocas, "VESTA_NO_PROMOTE_LOCAL_ALLOCAS", Emitted,
               Escape, Bool, Any)
VESTA_ENV_FLAG(NoPromoteRawAlloc, "VESTA_NO_PROMOTE_RAW_ALLOC", Emitted, Escape,
               Bool, Any)
VESTA_ENV_FLAG(NoSlab, "VESTA_NO_SLAB", Emitted, Escape, Bool, Any)
VESTA_ENV_FLAG(NoHostSlab, "VESTA_NO_HOST_SLAB", Emitted, Escape, Bool, Any)
VESTA_ENV_FLAG(EscapeDebug, "VESTA_ESCAPE_DEBUG", Report, Escape, Bool, Any)

/* -- Bucles --------------------------------------------------------------- */
VESTA_ENV_FLAG(NoUnroll, "VESTA_NO_UNROLL", Emitted, Loop, Bool, Any)
VESTA_ENV_FLAG(UnrollStats, "VESTA_UNROLL_STATS", Report, Loop, Bool, Any)

/* -- Vectorizacion y memoria en bloque ------------------------------------ */
VESTA_ENV_FLAG(NoVectorize, "VESTA_NO_VECTORIZE", Emitted, Vector, Bool, Any)
VESTA_ENV_FLAG(NoZmm, "VESTA_NO_ZMM", Emitted, Vector, Bool, Any)
VESTA_ENV_FLAG(NoBulkMemory, "VESTA_NO_BULK_MEMORY", Emitted, Vector, Bool, Any)

/* -- Ramas: SELECT contra salto ------------------------------------------- */
VESTA_ENV_FLAG(NoIfConversion, "VESTA_NO_IF_CONVERSION", Emitted, Branch, Bool,
               Any)
VESTA_ENV_FLAG(IfConversionAll, "VESTA_IF_CONVERSION_ALL", Emitted, Branch,
               Bool, Any)
VESTA_ENV_FLAG(BranchProfile, "VESTA_BRANCH_PROFILE", Emitted, Branch, Text,
               Any)

/* -- Ensamblador en linea ------------------------------------------------- */
VESTA_ENV_FLAG(AsmDse, "VESTA_ASM_DSE", Emitted, Asm, BoolOn, Any)
VESTA_ENV_FLAG(AsmLoc, "VESTA_ASM_LOC", Emitted, Asm, BoolOn, Any)
VESTA_ENV_FLAG(AsmNoLift, "VESTA_ASM_NO_LIFT", Emitted, Asm, Bool, Any)
VESTA_ENV_FLAG(AsmNoLiftSsa, "VESTA_ASM_NO_LIFT_SSA", Emitted, Asm, Bool, Any)
VESTA_ENV_FLAG(NoAsmBackend, "VESTA_NO_ASM_BACKEND", Emitted, Asm, Bool, Any)
VESTA_ENV_FLAG(AsmEffDebug, "VESTA_ASM_EFF_DEBUG", Report, Asm, Bool, Any)
VESTA_ENV_FLAG(AsmLiftDebug, "VESTA_ASM_LIFT_DEBUG", Report, Asm, Bool, Any)
VESTA_ENV_FLAG(AsmTrampDebug, "VESTA_ASM_TRAMP_DEBUG", Report, Asm, Bool, Any)
VESTA_ENV_FLAG(AsmDbGaps, "VESTA_ASM_DB_GAPS", Report, Asm, Bool, Any)
VESTA_ENV_FLAG(AsmFlujoDebug, "VESTA_ASMFLUJO_DEBUG", Report, Asm, Bool, Any)
VESTA_ENV_FLAG(VxAsmDebug, "VX_ASM_DEBUG", Report, Asm, Bool, Any)
VESTA_ENV_FLAG(NakedDebug, "VESTA_NAKED_DEBUG", Report, Asm, Bool, Any)

/* -- Comptime y precomputo del arranque ----------------------------------- */
VESTA_ENV_FLAG(NoCtpe, "VESTA_NO_CTPE", Emitted, Comptime, Bool, Any)
VESTA_ENV_FLAG(NoFiltroComptime, "VESTA_NO_FILTRO_COMPTIME", Emitted, Comptime,
               Bool, Any)
VESTA_ENV_FLAG(McPrebuilt, "VESTA_MC_PREBUILT", Emitted, Comptime, TextLive,
               Any)
VESTA_ENV_FLAG(McNoJit, "VESTA_MC_NO_JIT", Emitted, Comptime, Bool, Any)
VESTA_ENV_FLAG(CtpeDebug, "VESTA_CTPE_DEBUG", Report, Comptime, Bool, Any)
VESTA_ENV_FLAG(CtpeMs, "VESTA_CTPE_MS", Report, Comptime, Bool, Any)
VESTA_ENV_FLAG(ComptimeDebug, "VESTA_COMPTIME_DEBUG", Report, Comptime, Bool,
               Any)
VESTA_ENV_FLAG(ComptimeProbe, "VESTA_COMPTIME_PROBE", Report, Comptime, Bool,
               Any)
VESTA_ENV_FLAG(DumpComptimeUnit, "VESTA_DUMP_COMPTIME_UNIT", Report, Comptime,
               Bool, Any)
VESTA_ENV_FLAG(VolcarUnidad, "VESTA_VOLCAR_UNIDAD", Report, Comptime, Text, Any)
VESTA_ENV_FLAG(PruebaIrComptime, "VESTA_PRUEBA_IR_COMPTIME", Report, Comptime,
               Bool, Any)
VESTA_ENV_FLAG(ArtefactoTemprano, "VESTA_ARTEFACTO_TEMPRANO", Emitted, Comptime,
               Bool, Any)
VESTA_ENV_FLAG(McIdiomDebug, "VESTA_MC_IDIOM_DEBUG", Report, Comptime, Bool,
               Any)
VESTA_ENV_FLAG(McVerbose, "VESTA_MC_VERBOSE", Report, Comptime, Bool, Any)

/* -- Planificador de instrucciones ---------------------------------------- */
VESTA_ENV_FLAG(Sched, "VESTA_SCHED", Emitted, Scheduler, BoolOn, Any)
VESTA_ENV_FLAG(SchedEff, "VESTA_SCHED_EFF", Emitted, Scheduler, Bool, Any)
VESTA_ENV_FLAG(SchedShape, "VESTA_SCHED_SHAPE", Emitted, Scheduler, Bool, Any)
VESTA_ENV_FLAG(SchedStress, "VESTA_SCHED_STRESS", Emitted, Scheduler, Bool, Any)
VESTA_ENV_FLAG(SchedStats, "VESTA_SCHED_STATS", Report, Scheduler, Bool, Any)
VESTA_ENV_FLAG(SchedVerify, "VESTA_SCHED_VERIFY", Report, Scheduler, Bool, Any)

/* -- Asignacion de registros ---------------------------------------------- */
VESTA_ENV_FLAG(AsignadorMaquina, "VESTA_ASIGNADOR_MAQUINA", Emitted, RegAlloc,
               Bool, Any)
VESTA_ENV_FLAG(Belady, "VESTA_BELADY", Emitted, RegAlloc, BoolOn, Any)
VESTA_ENV_FLAG(Splitting, "VESTA_SPLITTING", Emitted, RegAlloc, Bool, Any)
VESTA_ENV_FLAG(Recovery, "VESTA_RECOVERY", Emitted, RegAlloc, BoolOn, Any)
VESTA_ENV_FLAG(VregNoSplit, "VESTA_VREG_NO_SPLIT", Emitted, RegAlloc, Bool, Any)
VESTA_ENV_FLAG(NoSsaCoalesce, "VESTA_NO_SSA_COALESCE", Emitted, RegAlloc, Bool,
               Any)
VESTA_ENV_FLAG(Arm64Vreg, "VESTA_ARM64_VREG", Emitted, RegAlloc, BoolOn, Any)
VESTA_ENV_FLAG(C2Vreg, "VESTA_C2_VREG", Emitted, RegAlloc, Bool, Any)
VESTA_ENV_FLAG(RematMeasure, "VESTA_REMAT_MEASURE", Report, RegAlloc, Bool, Any)
VESTA_ENV_FLAG(DeadDefReport, "VESTA_DEAD_DEF_REPORT", Report, RegAlloc, Text,
               Any)
VESTA_ENV_FLAG(DeadDefOnly, "VESTA_DEAD_DEF_ONLY", Emitted, Codegen, Text, Any)
VESTA_ENV_FLAG(VregDump, "VESTA_VREG_DUMP", Report, RegAlloc, Bool, Any)
VESTA_ENV_FLAG(VregsDebug, "VESTA_JIT_VREGS_DEBUG", Report, RegAlloc, Bool, Any)
VESTA_ENV_FLAG(SsaCoalDbg, "VESTA_SSA_COAL_DBG", Report, RegAlloc, Bool, Any)
VESTA_ENV_FLAG(RbankAsmDebug, "VESTA_RBANK_ASM_DEBUG", Report, RegAlloc, Bool,
               Any)

/* -- Emision de codigo maquina -------------------------------------------- */
VESTA_ENV_FLAG(NoPeephole, "VESTA_NO_PEEPHOLE", Emitted, Codegen, Bool, Any)
VESTA_ENV_FLAG(NoSib, "VESTA_NO_SIB", Emitted, Codegen, Bool, Any)
VESTA_ENV_FLAG(NoXorZero, "VESTA_NO_XORZERO", Emitted, Codegen, Bool, Any)
VESTA_ENV_FLAG(NoJmpFall, "VESTA_NO_JMPFALL", Emitted, Codegen, Bool, Any)
VESTA_ENV_FLAG(NoDeadDef, "VESTA_NO_DEADDEF", Emitted, Codegen, Bool, Any)
VESTA_ENV_FLAG(NoDirectTailJmp, "VESTA_NO_DIRECT_TAILJMP", Emitted, Codegen,
               Bool, Any)
VESTA_ENV_FLAG(NoPack, "VESTA_NO_PACK", Emitted, Codegen, Bool, Any)
VESTA_ENV_FLAG(NoWideHome, "VESTA_NO_WIDE_HOME", Emitted, Codegen, Bool, Any)
VESTA_ENV_FLAG(CbForceCall, "VESTA_CB_FORCE_CALL", Emitted, Codegen, Bool, Any)
VESTA_ENV_FLAG(VregCallbacks, "VESTA_VREG_CALLBACKS", Emitted, Codegen, BoolOn,
               Any)
VESTA_ENV_FLAG(SibDbg, "VESTA_SIB_DBG", Report, Codegen, Bool, Any)
VESTA_ENV_FLAG(Arm64Dump, "VESTA_ARM64_DUMP", Report, Codegen, Bool, Any)
VESTA_ENV_FLAG(AotDumpIr, "VESTA_AOT_DUMP_IR", Report, Codegen, Bool, Any)
VESTA_ENV_FLAG(LinkerProfile, "VESTA_LINKER_PROFILE", Report, Codegen, Bool,
               Any)

/* -- JIT: cambian el nativo que se genera al vuelo, no el .velb ----------- */
VESTA_ENV_FLAG(JitNoInlineAlloc, "VESTA_JIT_NO_INLINE_ALLOC", Emitted, Jit,
               Bool, Any)
VESTA_ENV_FLAG(JitNoInlineCallvirt, "VESTA_JIT_NO_INLINE_CALLVIRT", Emitted,
               Jit, Bool, Any)
VESTA_ENV_FLAG(JitNoInlineDeref, "VESTA_JIT_NO_INLINE_DEREF", Emitted, Jit,
               Bool, Any)
VESTA_ENV_FLAG(JitNoRegalloc, "VESTA_JIT_NO_REGALLOC", Emitted, Jit, Bool, Any)
VESTA_ENV_FLAG(JitNoFrameless, "VESTA_JIT_NO_FRAMELESS", Emitted, Jit, Bool,
               Any)
VESTA_ENV_FLAG(JitNoEspecializar, "VESTA_JIT_NO_ESPECIALIZAR", Emitted, Jit,
               Bool, Any)
VESTA_ENV_FLAG(JitVregIdiv, "VESTA_JIT_VREG_IDIV", Emitted, Jit, BoolOn, Any)
VESTA_ENV_FLAG(NoJitPgo, "VESTA_NO_JIT_PGO", Emitted, Jit, Bool, Any)
VESTA_ENV_FLAG(JitThreshold, "VESTA_JIT_THRESHOLD", Runtime, Jit, Int, Any)
VESTA_ENV_FLAG(JitTier2Delta, "VESTA_JIT_TIER2_DELTA", Runtime, Jit, Int, Any)
VESTA_ENV_FLAG(C2Threshold, "VESTA_C2_THRESHOLD", Runtime, Jit, Int, Any)
VESTA_ENV_FLAG(C2TierAll, "VESTA_C2_TIER_ALL", Runtime, Jit, Bool, Any)
VESTA_ENV_FLAG(OsrThreshold, "VESTA_OSR_THRESHOLD", Runtime, Jit, Int, Any)
VESTA_ENV_FLAG(OsrCount, "VESTA_OSR_COUNT", Runtime, Jit, Int, Any)
VESTA_ENV_FLAG(OsrOpt, "VESTA_OSR_OPT", Runtime, Jit, BoolOn, Any)
VESTA_ENV_FLAG(JitDisasm, "VESTA_JIT_DISASM", Report, Jit, Bool, Any)
VESTA_ENV_FLAG(JitDisasmRegs, "VESTA_JIT_DISASM_REGS", Report, Jit, Bool, Any)
VESTA_ENV_FLAG(JitAsmDump, "VESTA_JIT_ASM_DUMP", Report, Jit, Bool, Any)
VESTA_ENV_FLAG(JitStats, "VESTA_JIT_STATS", Report, Jit, Bool, Any)
VESTA_ENV_FLAG(JitTime, "VESTA_JIT_TIME", Report, Jit, Bool, Any)
VESTA_ENV_FLAG(JitRegallocDebug, "VESTA_JIT_REGALLOC_DEBUG", Report, Jit, Bool,
               Any)
VESTA_ENV_FLAG(JitEspecializarDebug, "VESTA_JIT_ESPECIALIZAR_DEBUG", Report,
               Jit, Bool, Any)
VESTA_ENV_FLAG(JitWarnUnsupported, "VESTA_JIT_WARN_UNSUPPORTED", Report, Jit,
               Bool, Any)
VESTA_ENV_FLAG(C2Log, "VESTA_C2_LOG", Report, Jit, Bool, Any)
VESTA_ENV_FLAG(OsrLog, "VESTA_OSR_LOG", Report, Jit, Bool, Any)
VESTA_ENV_FLAG(ProfileDump, "VESTA_PROFILE_DUMP", Report, Jit, Text, Any)

/* -- Recoleccion de basura (ejecucion) ------------------------------------ */
VESTA_ENV_FLAG(GcConservative, "VESTA_GC_CONSERVATIVE", Runtime, Gc, Bool, Any)
VESTA_ENV_FLAG(GcPreciseOnly, "VESTA_GC_PRECISE_ONLY", Runtime, Gc, Bool, Any)
VESTA_ENV_FLAG(GcCompactAlways, "VESTA_GC_COMPACT_ALWAYS", Runtime, Gc, Bool,
               Any)
VESTA_ENV_FLAG(GcCompactThreshold, "VESTA_GC_COMPACT_THRESHOLD", Runtime, Gc,
               Int, Any)
VESTA_ENV_FLAG(GcStress, "VESTA_GC_STRESS", Runtime, Gc, Bool, Any)
VESTA_ENV_FLAG(GcVerify, "VESTA_GC_VERIFY", Runtime, Gc, Bool, Any)
VESTA_ENV_FLAG(GcVerifyMove, "VESTA_GC_VERIFY_MOVE", Runtime, Gc, Bool, Any)
VESTA_ENV_FLAG(GcDebug, "VESTA_GC_DEBUG", Report, Gc, Bool, Any)
VESTA_ENV_FLAG(GcDebugBuffered, "VESTA_GC_DEBUG_BUFFERED", Report, Gc, Bool,
               Any)
VESTA_ENV_FLAG(GcInterpTrace, "VESTA_GC_INTERP_TRACE", Report, Gc, Bool, Any)
VESTA_ENV_FLAG(McGcInterval, "VESTA_MC_GC_INTERVAL", Runtime, Gc, Int, Any)
VESTA_ENV_FLAG(McGcTrace, "VESTA_MC_GC_TRACE", Report, Gc, Bool, Any)
VESTA_ENV_FLAG(HostAllocStats, "VESTA_HOST_ALLOC_STATS", Report, Gc, Bool, Any)

/* -- Reparto por hilos.  Cambia el COMO, no el QUE ------------------------ */
VESTA_ENV_FLAG(Paralelo, "VESTA_PARALELO", Speed, Parallel, BoolOn, Any)
VESTA_ENV_FLAG(ParaleloStats, "VESTA_PARALELO_STATS", Report, Parallel, Bool,
               Any)
VESTA_ENV_FLAG(ParallelCompile, "VX_PARALLEL_COMPILE", Speed, Parallel, Int,
               Any)

/* -- ASA: el conocimiento del programa ------------------------------------ */
VESTA_ENV_FLAG(AsaBounds, "VESTA_ASA_BOUNDS", Report, Asa, BoolOn, Any)
VESTA_ENV_FLAG(AsaCache, "VESTA_ASA_CACHE", Speed, Asa, Text, Any)
VESTA_ENV_FLAG(AsaFormas, "VESTA_ASA_FORMAS", Report, Asa, Bool, Any)
VESTA_ENV_FLAG(AsaHechosDebug, "VESTA_ASA_HECHOS_DEBUG", Report, Asa, Bool, Any)
VESTA_ENV_FLAG(BoundsDebug, "VESTA_BOUNDS_DEBUG", Report, Asa, Bool, Any)
VESTA_ENV_FLAG(FormaDebug, "VESTA_FORMA_DEBUG", Report, Asa, Bool, Any)
VESTA_ENV_FLAG(RpoDump, "VESTA_RPO_DUMP", Report, Asa, Bool, Any)

/* -- Caches: donde estan y si se usan ------------------------------------- */
VESTA_ENV_FLAG(CacheDir, "VX_CACHE_DIR", Location, Cache, Text, Any)
VESTA_ENV_FLAG(CasDir, "VX_CAS_DIR", Location, Cache, Text, Any)
VESTA_ENV_FLAG(NoCache, "VX_NO_CACHE", Speed, Cache, Bool, Any)
VESTA_ENV_FLAG(NoProjectCache, "VX_NO_PROJECT_CACHE", Speed, Cache, Bool, Any)
VESTA_ENV_FLAG(CacheFingerprint, "VX_CACHE_FINGERPRINT", Location, Cache, Text,
               Any)
VESTA_ENV_FLAG(McCacheTtlDays, "VESTA_MC_CACHE_TTL_DAYS", Location, Cache, Int,
               Any)
VESTA_ENV_FLAG(VerboseCache, "VX_VERBOSE_CACHE", Report, Cache, Bool, Any)
VESTA_ENV_FLAG(VerboseCompile, "VX_VERBOSE_COMPILE", Report, Cache, Bool, Any)
VESTA_ENV_FLAG(VerboseProjectCache, "VX_VERBOSE_PROJECT_CACHE", Report, Cache,
               Bool, Any)
VESTA_ENV_FLAG(DbgVxi, "VX_DBG_VXI", Report, Cache, Bool, Any)
VESTA_ENV_FLAG(DbgReg, "VX_DBG_REG", Report, Cache, Bool, Any)

/* -- Comprobaciones internas ---------------------------------------------- */
/* Verifica el IR recien construido contra sus propias reglas.  Cuesta un
 * recorrido del modulo, asi que no va por defecto. */
VESTA_ENV_FLAG(VerifyIr, "VESTA_VERIFY_IR", Report, None, Bool, Any)

/* -- Medicion transversal ------------------------------------------------- */
VESTA_ENV_FLAG(Times, "VESTA_TIMES", Report, None, Bool, Any)
VESTA_ENV_FLAG(Tramos, "VESTA_TRAMOS", Emitted, RegAlloc, BoolOn, Any)
VESTA_ENV_FLAG(DbgBpTrace, "VESTA_DBG_BP_TRACE", Report, None, Bool, Any)
VESTA_ENV_FLAG(NoColor, "NO_COLOR", Report, None, Bool, Any)

/* -- Donde vive lo instalado ---------------------------------------------- */
VESTA_ENV_FLAG(VxHome, "VX_HOME", Location, Paths, Text, Any)
VESTA_ENV_FLAG(VxPath, "VX_PATH", Location, Paths, Text, Any)
VESTA_ENV_FLAG(StdlibDir, "VX_STDLIB_DIR", Location, Paths, Text, Any)
VESTA_ENV_FLAG(VshPath, "VESTAVM_VSH_PATH", Location, Paths, Text, Any)

/* -- Del sistema operativo.  No son nuestras: no entran en ninguna huella - */
VESTA_ENV_FLAG(SysHome, "HOME", System, Paths, Text, Posix)
VESTA_ENV_FLAG(SysAppData, "APPDATA", System, Paths, Text, Windows)
VESTA_ENV_FLAG(SysUserProfile, "USERPROFILE", System, Paths, Text, Windows)
VESTA_ENV_FLAG(SysTemp, "TEMP", System, Paths, Text, Windows)
VESTA_ENV_FLAG(SysTmp, "TMP", System, Paths, Text, Windows)
VESTA_ENV_FLAG(SysPath, "PATH", System, Paths, Text, Any)
VESTA_ENV_FLAG(SysPathExt, "PATHEXT", System, Paths, Text, Windows)
VESTA_ENV_FLAG(SysRoot, "SystemRoot", System, Paths, Text, Windows)
/* Fecha con la que sellar lo que se genera, en segundos desde 1970.  Es el
 * mando ESTANDAR de los builds reproducibles, no uno nuestro: quien empaqueta
 * lo pone y espera que el resultado no dependa del reloj.  Sin el, no se sella
 * ninguna fecha -- el campo va a cero -- para que dos compilaciones del mismo
 * fuente den el mismo fichero. */
VESTA_ENV_FLAG(SourceDateEpoch, "SOURCE_DATE_EPOCH", System, Paths, Text, Any)
