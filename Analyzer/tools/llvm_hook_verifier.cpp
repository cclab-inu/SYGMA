#include "llvm/IR/Constants.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/KnownBits.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <climits>
#include <deque>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace llvm;

namespace {

struct Options {
  std::string Input;
  std::string Output;
};

struct Fact {
  std::string Kind;
  std::string Hook;
  std::string Callee;
  std::string Function;
  std::string SourceFunction;
  std::string SourceFile;
  unsigned SourceLine = 0;
  unsigned SourceColumn = 0;
  std::vector<std::string> InlinedAtFunctions;
  std::string Module;
  bool ResultUsed = false;
  bool ControlsBranch = false;
  bool ReachesReturn = false;
  bool MustReturnExact = false;
  bool MustReturnNegativeOnError = false;
  bool MustReturnNegativeOnFalse = false;
  bool MustReturnNegativeOnTrue = false;
  bool MustReturnNonnegativeOnZero = false;
  bool MustReturnNonnegativeOnPositive = false;
  bool MustPreserveNonnegativeSuccess = false;
  bool MustReturnValidPointerOnValidPointer = false;
  bool MustPreserveValidPointerSuccess = false;
  bool FunctionHasReturn = false;
  bool FunctionMustReturnNonnegative = false;
  bool FunctionMustReturnNonpositive = false;
  bool FunctionMustReturnNonNull = false;
  bool FunctionMustReturnValidPointer = false;
  bool FunctionMustReturnTrue = false;
  std::vector<unsigned> FunctionPreservedPointeeArguments;
  bool DoesNotAccessMemory = false;
  bool OnlyReadsMemory = false;
  std::set<std::string> UseKinds;
};

using PointeePreservationMap =
    std::unordered_map<const Function *, std::vector<bool>>;
using NonpositiveReturnMap =
    std::unordered_map<const Function *, bool>;

bool parseOptions(int argc, const char **argv, Options &Result) {
  for (int Index = 1; Index < argc; ++Index) {
    StringRef Argument(argv[Index]);
    auto ReadValue = [&](std::string &Destination) -> bool {
      if (Index + 1 >= argc) {
        errs() << "missing value for " << Argument << "\n";
        return false;
      }
      Destination = argv[++Index];
      return true;
    };
    if (Argument == "--input") {
      if (!ReadValue(Result.Input)) {
        return false;
      }
    } else if (Argument == "--output") {
      if (!ReadValue(Result.Output)) {
        return false;
      }
    } else if (Argument == "--help" || Argument == "-h") {
      outs() << "usage: llvm_hook_verifier --input MODULE --output FILE\n";
      return false;
    } else {
      errs() << "unknown argument: " << Argument << "\n";
      return false;
    }
  }
  if (Result.Input.empty() || Result.Output.empty()) {
    errs() << "--input and --output are required\n";
    return false;
  }
  return true;
}

Function *directCallee(CallBase &Call) {
  Value *Called = Call.getCalledOperand();
  if (!Called) {
    return nullptr;
  }
  return dyn_cast<Function>(Called->stripPointerCasts());
}

bool isDebugUser(const User *Use) {
  const auto *Call = dyn_cast<CallBase>(Use);
  if (!Call) {
    return false;
  }
  const Function *Callee = Call->getCalledFunction();
  return Callee && Callee->getName().startswith("llvm.dbg.");
}

void enqueueAllocaLoads(Value *Pointer, std::deque<Value *> &Queue,
                       Fact &Result) {
  Pointer = Pointer->stripPointerCasts();
  auto *Alloca = dyn_cast<AllocaInst>(Pointer);
  if (!Alloca) {
    Result.UseKinds.insert("store-nonlocal");
    return;
  }
  Result.UseKinds.insert("store-load");
  for (User *Use : Alloca->users()) {
    if (auto *Load = dyn_cast<LoadInst>(Use)) {
      Queue.push_back(Load);
    }
  }
}

enum class AbstractValue {
  Unknown,
  Negative,
  Zero,
  Positive,
  NullPointer,
  ValidPointer,
  ErrorPointer,
};

Value *stripValuePreservingCasts(Value *Current) {
  while (Current) {
    Current = Current->stripPointerCasts();
    if (auto *Freeze = dyn_cast<FreezeInst>(Current)) {
      Current = Freeze->getOperand(0);
      continue;
    }
    if (auto *SignExtend = dyn_cast<SExtInst>(Current)) {
      Current = SignExtend->getOperand(0);
      continue;
    }
    break;
  }
  return Current;
}

bool evaluateNonnegativeSourceRangeCompare(
    ICmpInst &Compare, CallBase &Source, AbstractValue SourceValue,
    bool &Result) {
  if (SourceValue != AbstractValue::Zero &&
      SourceValue != AbstractValue::Positive) {
    return false;
  }
  CmpInst::Predicate Predicate = Compare.getPredicate();
  if (Predicate != CmpInst::ICMP_ULT &&
      Predicate != CmpInst::ICMP_ULE) {
    return false;
  }
  auto *Threshold = dyn_cast<ConstantInt>(Compare.getOperand(1));
  auto *Add = dyn_cast<BinaryOperator>(Compare.getOperand(0));
  if (!Threshold || !Add || Add->getOpcode() != Instruction::Add ||
      !Add->getType()->isIntegerTy()) {
    return false;
  }
  Value *CandidateSource = nullptr;
  const ConstantInt *Offset = nullptr;
  for (unsigned Index = 0; Index < 2; ++Index) {
    if (stripValuePreservingCasts(Add->getOperand(Index)) == &Source) {
      CandidateSource = Add->getOperand(Index);
      Offset = dyn_cast<ConstantInt>(Add->getOperand(1 - Index));
      break;
    }
  }
  if (!CandidateSource || !Offset ||
      Offset->getValue().isNegative() ||
      Threshold->getValue().isNegative()) {
    return false;
  }
  unsigned Bits = Add->getType()->getIntegerBitWidth();
  if (Bits == 0 || Bits > 64) {
    return false;
  }
  uint64_t UnsignedMax =
      Bits == 64 ? UINT64_MAX : ((uint64_t{1} << Bits) - 1);
  uint64_t SignedMax =
      Bits == 64 ? static_cast<uint64_t>(INT64_MAX)
                 : ((uint64_t{1} << (Bits - 1)) - 1);
  uint64_t OffsetValue = Offset->getValue().getZExtValue();
  uint64_t ThresholdValue = Threshold->getValue().getZExtValue();
  uint64_t SourceMinimum =
      SourceValue == AbstractValue::Zero ? 0 : 1;
  if (OffsetValue > UnsignedMax - SignedMax ||
      OffsetValue > UnsignedMax - SourceMinimum) {
    return false;
  }
  uint64_t Minimum = SourceMinimum + OffsetValue;
  uint64_t Maximum = SignedMax + OffsetValue;
  if (Predicate == CmpInst::ICMP_ULT) {
    if (Minimum >= ThresholdValue) {
      Result = false;
      return true;
    }
    if (Maximum < ThresholdValue) {
      Result = true;
      return true;
    }
    return false;
  }
  if (Minimum > ThresholdValue) {
    Result = false;
    return true;
  }
  if (Maximum <= ThresholdValue) {
    Result = true;
    return true;
  }
  return false;
}

AbstractValue evaluateValue(
    Value *Current, CallBase &Source, AbstractValue SourceValue,
    BasicBlock *Predecessor, std::unordered_set<const Value *> &Active) {
  if (!Current) {
    return AbstractValue::Unknown;
  }
  Current = Current->stripPointerCasts();
  if (Current == &Source) {
    return SourceValue;
  }
  if (!Active.insert(Current).second) {
    return AbstractValue::Unknown;
  }
  auto Finish = [&](AbstractValue Result) {
    Active.erase(Current);
    return Result;
  };
  if (auto *Constant = dyn_cast<ConstantInt>(Current)) {
    if (Constant->isZero()) {
      return Finish(AbstractValue::Zero);
    }
    if (Constant->isNegative()) {
      return Finish(AbstractValue::Negative);
    }
    return Finish(AbstractValue::Positive);
  }
  if (isa<ConstantPointerNull>(Current)) {
    return Finish(AbstractValue::NullPointer);
  }
  if (isa<GlobalValue>(Current)) {
    return Finish(AbstractValue::ValidPointer);
  }
  if (auto *SignExtend = dyn_cast<SExtInst>(Current)) {
    AbstractValue Operand =
        evaluateValue(SignExtend->getOperand(0), Source, SourceValue,
                      Predecessor, Active);
    if (SignExtend->getSrcTy()->isIntegerTy(1) &&
        Operand == AbstractValue::Positive) {
      return Finish(AbstractValue::Negative);
    }
    return Finish(Operand);
  }
  if (auto *ZeroExtend = dyn_cast<ZExtInst>(Current)) {
    AbstractValue Operand =
        evaluateValue(ZeroExtend->getOperand(0), Source, SourceValue,
                      Predecessor, Active);
    if (Operand == AbstractValue::Negative) {
      return Finish(AbstractValue::Unknown);
    }
    return Finish(Operand);
  }
  if (auto *Freeze = dyn_cast<FreezeInst>(Current)) {
    return Finish(evaluateValue(Freeze->getOperand(0), Source, SourceValue,
                                Predecessor, Active));
  }
  if (auto *Phi = dyn_cast<PHINode>(Current)) {
    if (!Predecessor) {
      return Finish(AbstractValue::Unknown);
    }
    int IncomingIndex = Phi->getBasicBlockIndex(Predecessor);
    if (IncomingIndex < 0) {
      return Finish(AbstractValue::Unknown);
    }
    Value *Incoming = Phi->getIncomingValue(IncomingIndex);
    return Finish(evaluateValue(Incoming, Source, SourceValue, Predecessor,
                                Active));
  }
  if (auto *Compare = dyn_cast<ICmpInst>(Current)) {
    bool RangeResult = false;
    if (evaluateNonnegativeSourceRangeCompare(
            *Compare, Source, SourceValue, RangeResult)) {
      return Finish(RangeResult ? AbstractValue::Positive
                                : AbstractValue::Zero);
    }
    Value *LeftOperand = Compare->getOperand(0)->stripPointerCasts();
    Value *RightOperand = Compare->getOperand(1)->stripPointerCasts();
    if (LeftOperand == RightOperand) {
      switch (Compare->getPredicate()) {
      case CmpInst::ICMP_EQ:
      case CmpInst::ICMP_SLE:
      case CmpInst::ICMP_SGE:
      case CmpInst::ICMP_ULE:
      case CmpInst::ICMP_UGE:
        return Finish(AbstractValue::Positive);
      case CmpInst::ICMP_NE:
      case CmpInst::ICMP_SLT:
      case CmpInst::ICMP_SGT:
      case CmpInst::ICMP_ULT:
      case CmpInst::ICMP_UGT:
        return Finish(AbstractValue::Zero);
      default:
        break;
      }
    }
    if (auto *LeftConstant = dyn_cast<ConstantInt>(LeftOperand)) {
      if (auto *RightConstant = dyn_cast<ConstantInt>(RightOperand)) {
        bool Result = ICmpInst::compare(
            LeftConstant->getValue(), RightConstant->getValue(),
            Compare->getPredicate());
        return Finish(Result ? AbstractValue::Positive
                             : AbstractValue::Zero);
      }
    }
    AbstractValue Left = evaluateValue(Compare->getOperand(0), Source,
                                       SourceValue, Predecessor, Active);
    AbstractValue Right = evaluateValue(Compare->getOperand(1), Source,
                                        SourceValue, Predecessor, Active);
    bool Known = true;
    bool Result = false;
    switch (Compare->getPredicate()) {
    case CmpInst::ICMP_EQ:
      Known = Left != AbstractValue::Unknown &&
              Right != AbstractValue::Unknown;
      if (Known && Left != Right) {
        Result = false;
      } else if (Known && (Left == AbstractValue::Zero ||
                           Left == AbstractValue::NullPointer)) {
        Result = true;
      } else {
        Known = false;
      }
      break;
    case CmpInst::ICMP_NE:
      Known = Left != AbstractValue::Unknown &&
              Right != AbstractValue::Unknown;
      if (Known && Left != Right) {
        Result = true;
      } else if (Known && (Left == AbstractValue::Zero ||
                           Left == AbstractValue::NullPointer)) {
        Result = false;
      } else {
        Known = false;
      }
      break;
    case CmpInst::ICMP_SLT:
      if (Right == AbstractValue::Zero && Left == AbstractValue::Negative) {
        Result = true;
      } else if (Right == AbstractValue::Zero &&
                 (Left == AbstractValue::Zero ||
                  Left == AbstractValue::Positive)) {
        Result = false;
      } else {
        Known = false;
      }
      break;
    case CmpInst::ICMP_SLE:
      if (Right == AbstractValue::Zero &&
          (Left == AbstractValue::Negative ||
           Left == AbstractValue::Zero)) {
        Result = true;
      } else if (Right == AbstractValue::Zero &&
                 Left == AbstractValue::Positive) {
        Result = false;
      } else {
        Known = false;
      }
      break;
    case CmpInst::ICMP_SGE:
      if (Right == AbstractValue::Zero && Left == AbstractValue::Negative) {
        Result = false;
      } else if (Right == AbstractValue::Zero &&
                 (Left == AbstractValue::Zero ||
                  Left == AbstractValue::Positive)) {
        Result = true;
      } else {
        Known = false;
      }
      break;
    case CmpInst::ICMP_SGT:
      if (Right == AbstractValue::Zero &&
          Left == AbstractValue::Positive) {
        Result = true;
      } else if (Right == AbstractValue::Zero &&
                 (Left == AbstractValue::Negative ||
                  Left == AbstractValue::Zero)) {
        Result = false;
      } else {
        Known = false;
      }
      break;
    default:
      Known = false;
      break;
    }
    if (!Known) {
      return Finish(AbstractValue::Unknown);
    }
    return Finish(Result ? AbstractValue::Positive : AbstractValue::Zero);
  }
  if (auto *Binary = dyn_cast<BinaryOperator>(Current)) {
    if (!Binary->getType()->isIntegerTy(1)) {
      return Finish(AbstractValue::Unknown);
    }
    AbstractValue Left = evaluateValue(Binary->getOperand(0), Source,
                                       SourceValue, Predecessor, Active);
    AbstractValue Right = evaluateValue(Binary->getOperand(1), Source,
                                        SourceValue, Predecessor, Active);
    if (Left == AbstractValue::Unknown ||
        Right == AbstractValue::Unknown ||
        Left == AbstractValue::Negative ||
        Right == AbstractValue::Negative) {
      return Finish(AbstractValue::Unknown);
    }
    bool LeftValue = Left == AbstractValue::Positive;
    bool RightValue = Right == AbstractValue::Positive;
    bool Result = false;
    switch (Binary->getOpcode()) {
    case Instruction::And:
      Result = LeftValue && RightValue;
      break;
    case Instruction::Or:
      Result = LeftValue || RightValue;
      break;
    case Instruction::Xor:
      Result = LeftValue != RightValue;
      break;
    default:
      return Finish(AbstractValue::Unknown);
    }
    return Finish(Result ? AbstractValue::Positive : AbstractValue::Zero);
  }
  if (auto *Select = dyn_cast<SelectInst>(Current)) {
    AbstractValue Condition = evaluateValue(
        Select->getCondition(), Source, SourceValue, Predecessor, Active);
    if (Condition == AbstractValue::Unknown ||
        Condition == AbstractValue::Negative) {
      return Finish(AbstractValue::Unknown);
    }
    Value *Selected = Condition == AbstractValue::Zero
                          ? Select->getFalseValue()
                          : Select->getTrueValue();
    return Finish(evaluateValue(Selected, Source, SourceValue, Predecessor,
                                Active));
  }
  return Finish(AbstractValue::Unknown);
}

bool isIgnoredIRCall(const CallBase &Call) {
  const Function *Callee = Call.getCalledFunction();
  return Callee && (Callee->isIntrinsic() ||
                    Callee->getName().startswith("llvm.dbg.") ||
                    Callee->getName().startswith("llvm.lifetime."));
}

enum class ReturnRequirement {
  Negative,
  Nonnegative,
  ValidPointer,
};

bool satisfiesReturnRequirement(AbstractValue Value,
                                ReturnRequirement Requirement) {
  switch (Requirement) {
  case ReturnRequirement::Negative:
    return Value == AbstractValue::Negative;
  case ReturnRequirement::Nonnegative:
    return Value == AbstractValue::Zero ||
           Value == AbstractValue::Positive;
  case ReturnRequirement::ValidPointer:
    return Value == AbstractValue::ValidPointer;
  }
  return false;
}

bool mustReturnUnder(CallBase &Source, AbstractValue SourceValue,
                     ReturnRequirement Requirement) {
  struct State {
    BasicBlock *Block = nullptr;
    BasicBlock *Predecessor = nullptr;
    Instruction *StartAfter = nullptr;
  };
  std::deque<State> Queue;
  Queue.push_back(
      {Source.getParent(), nullptr, dyn_cast<Instruction>(&Source)});
  std::set<std::tuple<const BasicBlock *, const BasicBlock *,
                      const Instruction *>>
      Visited;
  bool SawReturn = false;
  unsigned Steps = 0;
  while (!Queue.empty() && Steps++ < 10000) {
    State Current = Queue.front();
    Queue.pop_front();
    auto Key = std::make_tuple(Current.Block, Current.Predecessor,
                               Current.StartAfter);
    if (!Visited.insert(Key).second) {
      return false;
    }
    bool Started = Current.StartAfter == nullptr;
    for (Instruction &InstructionValue : *Current.Block) {
      if (!Started) {
        if (&InstructionValue == Current.StartAfter) {
          Started = true;
        }
        continue;
      }
      if (&InstructionValue == &Source) {
        continue;
      }
      if (auto *Return = dyn_cast<ReturnInst>(&InstructionValue)) {
        std::unordered_set<const Value *> Active;
        AbstractValue Value =
            evaluateValue(Return->getReturnValue(), Source, SourceValue,
                          Current.Predecessor, Active);
        if (!satisfiesReturnRequirement(Value, Requirement)) {
          return false;
        }
        SawReturn = true;
        break;
      }
      if (auto *Branch = dyn_cast<BranchInst>(&InstructionValue)) {
        if (!Branch->isConditional()) {
          Queue.push_back(
              {Branch->getSuccessor(0), Current.Block, nullptr});
          break;
        }
        std::unordered_set<const Value *> Active;
        AbstractValue Condition = evaluateValue(
            Branch->getCondition(), Source, SourceValue, Current.Predecessor,
            Active);
        if (Condition == AbstractValue::Zero) {
          Queue.push_back(
              {Branch->getSuccessor(1), Current.Block, nullptr});
        } else if (Condition == AbstractValue::Positive) {
          Queue.push_back(
              {Branch->getSuccessor(0), Current.Block, nullptr});
        } else {
          Queue.push_back(
              {Branch->getSuccessor(0), Current.Block, nullptr});
          Queue.push_back(
              {Branch->getSuccessor(1), Current.Block, nullptr});
        }
        break;
      }
      if (auto *Switch = dyn_cast<SwitchInst>(&InstructionValue)) {
        std::unordered_set<const Value *> Active;
        AbstractValue Condition = evaluateValue(
            Switch->getCondition(), Source, SourceValue,
            Current.Predecessor, Active);
        if (Condition == AbstractValue::Unknown) {
          for (BasicBlock *Successor : successors(Current.Block)) {
            Queue.push_back({Successor, Current.Block, nullptr});
          }
          break;
        }
        bool DefaultPossible = true;
        for (auto Case : Switch->cases()) {
          const ConstantInt *CaseValue = Case.getCaseValue();
          AbstractValue CaseAbstract =
              CaseValue->isZero()
                  ? AbstractValue::Zero
                  : (CaseValue->isNegative()
                         ? AbstractValue::Negative
                         : AbstractValue::Positive);
          if (CaseAbstract == Condition) {
            Queue.push_back(
                {Case.getCaseSuccessor(), Current.Block, nullptr});
          }
          if (Condition == AbstractValue::Zero &&
              CaseValue->isZero()) {
            DefaultPossible = false;
          }
        }
        if (DefaultPossible) {
          Queue.push_back(
              {Switch->getDefaultDest(), Current.Block, nullptr});
        }
        break;
      }
      if (InstructionValue.isTerminator() &&
          !isa<ReturnInst>(&InstructionValue)) {
        return false;
      }
    }
  }
  return Steps < 10000 && SawReturn;
}

bool mustReturnNegativeUnder(CallBase &Source,
                             AbstractValue SourceValue) {
  return mustReturnUnder(Source, SourceValue,
                         ReturnRequirement::Negative);
}

bool mustReturnNonnegativeUnder(CallBase &Source,
                                AbstractValue SourceValue) {
  return mustReturnUnder(Source, SourceValue,
                         ReturnRequirement::Nonnegative);
}

bool mustReturnValidPointerUnder(CallBase &Source,
                                 AbstractValue SourceValue) {
  return mustReturnUnder(Source, SourceValue,
                         ReturnRequirement::ValidPointer);
}

std::string debugFilePath(const DILocalScope *Scope) {
  if (!Scope || !Scope->getFile()) {
    return {};
  }
  const DIFile *File = Scope->getFile();
  SmallString<256> Path(File->getDirectory());
  if (!File->getFilename().empty()) {
    sys::path::append(Path, File->getFilename());
  }
  sys::path::remove_dots(Path, true);
  return Path.str().str();
}

void addDebugProvenance(CallBase &Call, Fact &Result) {
  const DILocation *Location = Call.getDebugLoc().get();
  if (!Location) {
    Result.SourceFunction = Result.Function;
    return;
  }
  Result.SourceLine = Location->getLine();
  Result.SourceColumn = Location->getColumn();
  if (const auto *Scope = dyn_cast_or_null<DILocalScope>(Location->getScope())) {
    Result.SourceFile = debugFilePath(Scope);
    if (const DISubprogram *Subprogram = Scope->getSubprogram()) {
      Result.SourceFunction = Subprogram->getName().str();
    }
  }
  if (Result.SourceFunction.empty()) {
    Result.SourceFunction = Result.Function;
  }
  for (const DILocation *InlinedAt = Location->getInlinedAt(); InlinedAt;
       InlinedAt = InlinedAt->getInlinedAt()) {
    const auto *Scope =
        dyn_cast_or_null<DILocalScope>(InlinedAt->getScope());
    if (!Scope || !Scope->getSubprogram()) {
      continue;
    }
    Result.InlinedAtFunctions.push_back(
        Scope->getSubprogram()->getName().str());
  }
}

void addFunctionDebugProvenance(Function &FunctionValue, Fact &Result) {
  const DISubprogram *Subprogram = FunctionValue.getSubprogram();
  if (!Subprogram) {
    Result.SourceFunction = Result.Function;
    return;
  }
  Result.SourceFunction = Subprogram->getName().str();
  Result.SourceFile = debugFilePath(Subprogram);
  Result.SourceLine = Subprogram->getLine();
  if (Result.SourceFunction.empty()) {
    Result.SourceFunction = Result.Function;
  }
}

bool callArgumentOnlyReads(const CallBase &Call, unsigned ArgumentIndex) {
  if (Call.doesNotAccessMemory() || Call.onlyReadsMemory()) {
    return true;
  }
  return Call.paramHasAttr(ArgumentIndex, Attribute::ReadOnly) ||
         Call.paramHasAttr(ArgumentIndex, Attribute::ReadNone);
}

bool functionPreservesPointeeArgument(
    Function &FunctionValue, unsigned ArgumentIndex,
    const PointeePreservationMap &Preservation) {
  if (ArgumentIndex >= FunctionValue.arg_size()) {
    return false;
  }
  Argument *Root = FunctionValue.getArg(ArgumentIndex);
  if (!Root->getType()->isPointerTy()) {
    return false;
  }

  std::deque<Value *> Queue;
  std::unordered_set<const Value *> Seen;
  Queue.push_back(Root);
  Seen.insert(Root);
  while (!Queue.empty()) {
    Value *Current = Queue.front();
    Queue.pop_front();
    for (User *Use : Current->users()) {
      auto *InstructionValue = dyn_cast<Instruction>(Use);
      if (!InstructionValue ||
          InstructionValue->getFunction() != &FunctionValue) {
        return false;
      }
      if (isa<GetElementPtrInst>(InstructionValue) ||
          isa<BitCastInst>(InstructionValue) ||
          isa<AddrSpaceCastInst>(InstructionValue) ||
          isa<PHINode>(InstructionValue) ||
          isa<SelectInst>(InstructionValue) ||
          isa<PtrToIntInst>(InstructionValue) ||
          isa<IntToPtrInst>(InstructionValue)) {
        if (Seen.insert(InstructionValue).second) {
          Queue.push_back(InstructionValue);
        }
        continue;
      }
      if (auto *Load = dyn_cast<LoadInst>(InstructionValue)) {
        if (Load->getPointerOperand() == Current) {
          continue;
        }
        return false;
      }
      if (auto *Store = dyn_cast<StoreInst>(InstructionValue)) {
        if (Store->getPointerOperand() == Current ||
            Store->getValueOperand() == Current) {
          return false;
        }
        continue;
      }
      if (isa<AtomicCmpXchgInst>(InstructionValue) ||
          isa<AtomicRMWInst>(InstructionValue)) {
        return false;
      }
      if (auto *Memory = dyn_cast<MemIntrinsic>(InstructionValue)) {
        if (Memory->getRawDest() == Current) {
          return false;
        }
        if (auto *Transfer = dyn_cast<MemTransferInst>(Memory)) {
          if (Transfer->getRawSource() == Current) {
            continue;
          }
        }
        return false;
      }
      if (auto *Call = dyn_cast<CallBase>(InstructionValue)) {
        for (unsigned Index = 0; Index < Call->arg_size(); ++Index) {
          if (Call->getArgOperand(Index) != Current) {
            continue;
          }
          if (callArgumentOnlyReads(*Call, Index)) {
            continue;
          }
          Function *Callee = directCallee(*Call);
          if (!Callee || Callee->isDeclaration()) {
            return false;
          }
          auto Summary = Preservation.find(Callee);
          if (Summary == Preservation.end() ||
              Index >= Summary->second.size() ||
              !Summary->second[Index]) {
            return false;
          }
        }
        continue;
      }
      if (isa<ICmpInst>(InstructionValue) ||
          isa<ReturnInst>(InstructionValue)) {
        continue;
      }
      return false;
    }
  }
  return true;
}

PointeePreservationMap computePointeePreservation(Module &ModuleValue) {
  PointeePreservationMap Result;
  for (Function &FunctionValue : ModuleValue) {
    if (FunctionValue.isDeclaration()) {
      continue;
    }
    std::vector<bool> Arguments(FunctionValue.arg_size(), false);
    for (unsigned Index = 0; Index < FunctionValue.arg_size(); ++Index) {
      Arguments[Index] =
          FunctionValue.getArg(Index)->getType()->isPointerTy();
    }
    Result.emplace(&FunctionValue, std::move(Arguments));
  }

  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (Function &FunctionValue : ModuleValue) {
      if (FunctionValue.isDeclaration()) {
        continue;
      }
      std::vector<bool> &Arguments = Result[&FunctionValue];
      for (unsigned Index = 0; Index < Arguments.size(); ++Index) {
        if (!Arguments[Index] ||
            functionPreservesPointeeArgument(
                FunctionValue, Index, Result)) {
          continue;
        }
        Arguments[Index] = false;
        Changed = true;
      }
    }
  }
  return Result;
}

bool valueMustBeNonpositive(
    Value *ValueToCheck, Function &FunctionValue,
    const NonpositiveReturnMap &Summaries, const DataLayout &Layout,
    AssumptionCache &Assumptions, DominatorTree &Dominators,
    const Instruction *Context,
    std::unordered_set<const Value *> &Active) {
  if (!ValueToCheck || !ValueToCheck->getType()->isIntegerTy() ||
      !Active.insert(ValueToCheck).second) {
    return false;
  }
  auto Finish = [&](bool Result) {
    Active.erase(ValueToCheck);
    return Result;
  };
  if (auto *Constant = dyn_cast<ConstantInt>(ValueToCheck)) {
    return Finish(Constant->isZero() || Constant->isNegative());
  }
  if (isKnownNegative(ValueToCheck, Layout, 0, &Assumptions, Context,
                      &Dominators) ||
      computeKnownBits(ValueToCheck, Layout, 0, &Assumptions, Context,
                       &Dominators)
          .isZero()) {
    return Finish(true);
  }
  if (auto *Call = dyn_cast<CallBase>(ValueToCheck)) {
    Function *Callee = directCallee(*Call);
    auto Found = Summaries.find(Callee);
    return Finish(Callee && Found != Summaries.end() && Found->second);
  }
  if (auto *Phi = dyn_cast<PHINode>(ValueToCheck)) {
    if (Phi->getNumIncomingValues() == 0) {
      return Finish(false);
    }
    for (Value *Incoming : Phi->incoming_values()) {
      if (!valueMustBeNonpositive(
              Incoming, FunctionValue, Summaries, Layout, Assumptions,
              Dominators, Context, Active)) {
        return Finish(false);
      }
    }
    return Finish(true);
  }
  if (auto *Select = dyn_cast<SelectInst>(ValueToCheck)) {
    bool TrueNonpositive = valueMustBeNonpositive(
        Select->getTrueValue(), FunctionValue, Summaries, Layout,
        Assumptions, Dominators, Context, Active);
    bool FalseNonpositive = valueMustBeNonpositive(
        Select->getFalseValue(), FunctionValue, Summaries, Layout,
        Assumptions, Dominators, Context, Active);
    return Finish(TrueNonpositive && FalseNonpositive);
  }
  if (auto *SignExtend = dyn_cast<SExtInst>(ValueToCheck)) {
    return Finish(valueMustBeNonpositive(
        SignExtend->getOperand(0), FunctionValue, Summaries, Layout,
        Assumptions, Dominators, Context, Active));
  }
  if (auto *Freeze = dyn_cast<FreezeInst>(ValueToCheck)) {
    return Finish(valueMustBeNonpositive(
        Freeze->getOperand(0), FunctionValue, Summaries, Layout,
        Assumptions, Dominators, Context, Active));
  }
  if (auto *Binary = dyn_cast<BinaryOperator>(ValueToCheck)) {
    auto *Zero = dyn_cast<ConstantInt>(Binary->getOperand(0));
    if (Binary->getOpcode() == Instruction::Sub &&
        Zero && Zero->isZero() &&
        isKnownNonNegative(Binary->getOperand(1), Layout, 0,
                           &Assumptions, Context, &Dominators)) {
      return Finish(true);
    }
  }
  return Finish(false);
}

bool functionMustReturnNonpositive(
    Function &FunctionValue,
    const NonpositiveReturnMap &Summaries) {
  if (FunctionValue.isDeclaration() ||
      !FunctionValue.getReturnType()->isIntegerTy()) {
    return false;
  }
  AssumptionCache Assumptions(FunctionValue);
  DominatorTree Dominators(FunctionValue);
  const DataLayout &Layout = FunctionValue.getParent()->getDataLayout();
  bool SawReturn = false;
  for (BasicBlock &Block : FunctionValue) {
    auto *Return = dyn_cast<ReturnInst>(Block.getTerminator());
    if (!Return) {
      continue;
    }
    SawReturn = true;
    std::unordered_set<const Value *> Active;
    if (!valueMustBeNonpositive(
            Return->getReturnValue(), FunctionValue, Summaries, Layout,
            Assumptions, Dominators, Return, Active)) {
      return false;
    }
  }
  return SawReturn;
}

NonpositiveReturnMap computeNonpositiveReturns(
    Module &ModuleValue) {
  NonpositiveReturnMap Result;
  for (Function &FunctionValue : ModuleValue) {
    if (!FunctionValue.isDeclaration()) {
      Result[&FunctionValue] = false;
    }
  }
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (Function &FunctionValue : ModuleValue) {
      if (FunctionValue.isDeclaration() || Result[&FunctionValue] ||
          !functionMustReturnNonpositive(FunctionValue, Result)) {
        continue;
      }
      Result[&FunctionValue] = true;
      Changed = true;
    }
  }
  return Result;
}

Fact analyzeFunctionReturns(
    Function &FunctionValue, StringRef ModuleName,
    const PointeePreservationMap &PointeePreservation,
    const NonpositiveReturnMap &NonpositiveReturns) {
  Fact Result;
  Result.Kind = "function_summary";
  Result.Function = FunctionValue.getName().str();
  Result.Module = ModuleName.str();
  addFunctionDebugProvenance(FunctionValue, Result);

  Type *ReturnType = FunctionValue.getReturnType();
  bool IntegerReturn = ReturnType->isIntegerTy();
  bool BooleanReturn = ReturnType->isIntegerTy(1);
  bool PointerReturn = ReturnType->isPointerTy();
  bool AllNonnegative = IntegerReturn;
  bool AllNonNull = PointerReturn;
  bool AllTrue = BooleanReturn;
  AssumptionCache Assumptions(FunctionValue);
  DominatorTree Dominators(FunctionValue);
  const DataLayout &Layout = FunctionValue.getParent()->getDataLayout();

  for (BasicBlock &Block : FunctionValue) {
    auto *Return = dyn_cast<ReturnInst>(Block.getTerminator());
    if (!Return) {
      continue;
    }
    Result.FunctionHasReturn = true;
    Value *Value = Return->getReturnValue();
    if (IntegerReturn) {
      AllNonnegative =
          AllNonnegative && Value &&
          isKnownNonNegative(Value, Layout, 0, &Assumptions, Return,
                             &Dominators);
    }
    if (PointerReturn) {
      AllNonNull =
          AllNonNull && Value &&
          isKnownNonZero(Value, Layout, 0, &Assumptions, Return,
                         &Dominators);
    }
    if (BooleanReturn) {
      AllTrue =
          AllTrue && Value &&
          isKnownNonZero(Value, Layout, 0, &Assumptions, Return,
                         &Dominators);
    }
  }
  Result.FunctionMustReturnNonnegative =
      Result.FunctionHasReturn && AllNonnegative;
  auto Nonpositive = NonpositiveReturns.find(&FunctionValue);
  Result.FunctionMustReturnNonpositive =
      Nonpositive != NonpositiveReturns.end() && Nonpositive->second;
  Result.FunctionMustReturnNonNull =
      Result.FunctionHasReturn && AllNonNull;
  Result.FunctionMustReturnTrue =
      Result.FunctionHasReturn && AllTrue;
  auto Preserved = PointeePreservation.find(&FunctionValue);
  if (Preserved != PointeePreservation.end()) {
    for (unsigned Index = 0; Index < Preserved->second.size(); ++Index) {
      if (Preserved->second[Index]) {
        Result.FunctionPreservedPointeeArguments.push_back(Index);
      }
    }
  }
  return Result;
}

Fact analyzeCall(CallBase &Call, StringRef Callee, StringRef ModuleName) {
  Fact Result;
  Result.Kind = Callee.startswith("security_") ? "hook" : "call";
  Result.Callee = Callee.str();
  if (Result.Kind == "hook") {
    Result.Hook = Result.Callee;
  }
  Result.Function = Call.getFunction()->getName().str();
  Result.Module = ModuleName.str();
  addDebugProvenance(Call, Result);
  Result.DoesNotAccessMemory = Call.doesNotAccessMemory();
  Result.OnlyReadsMemory = Call.onlyReadsMemory();

  std::deque<Value *> Queue;
  std::unordered_set<const Value *> Visited;
  Queue.push_back(&Call);
  unsigned Steps = 0;
  while (!Queue.empty() && Steps++ < 10000) {
    Value *Current = Queue.front();
    Queue.pop_front();
    if (!Visited.insert(Current).second) {
      continue;
    }
    for (User *Use : Current->users()) {
      if (isDebugUser(Use)) {
        continue;
      }
      Result.ResultUsed = true;
      if (auto *Branch = dyn_cast<BranchInst>(Use)) {
        if (Branch->isConditional() && Branch->getCondition() == Current) {
          Result.ControlsBranch = true;
          Result.UseKinds.insert("branch");
        }
        continue;
      }
      if (auto *Switch = dyn_cast<SwitchInst>(Use)) {
        if (Switch->getCondition() == Current) {
          Result.ControlsBranch = true;
          Result.UseKinds.insert("switch");
        }
        continue;
      }
      if (auto *Return = dyn_cast<ReturnInst>(Use)) {
        if (Return->getReturnValue() == Current) {
          Result.ReachesReturn = true;
          Result.UseKinds.insert("return");
        }
        continue;
      }
      if (auto *Store = dyn_cast<StoreInst>(Use)) {
        if (Store->getValueOperand() == Current) {
          enqueueAllocaLoads(Store->getPointerOperand(), Queue, Result);
        }
        continue;
      }
      if (isa<ICmpInst>(Use) || isa<FCmpInst>(Use)) {
        Result.UseKinds.insert("compare");
        Queue.push_back(cast<Value>(Use));
        continue;
      }
      if (isa<PHINode>(Use)) {
        Result.UseKinds.insert("phi");
        Queue.push_back(cast<Value>(Use));
        continue;
      }
      if (isa<SelectInst>(Use)) {
        Result.UseKinds.insert("select");
        Queue.push_back(cast<Value>(Use));
        continue;
      }
      if (isa<CastInst>(Use) || isa<BinaryOperator>(Use) ||
          isa<UnaryInstruction>(Use) || isa<FreezeInst>(Use)) {
        Result.UseKinds.insert("ssa-transform");
        Queue.push_back(cast<Value>(Use));
        continue;
      }
      if (isa<CallBase>(Use)) {
        Result.UseKinds.insert("call-argument");
        continue;
      }
      if (isa<Instruction>(Use)) {
        Result.UseKinds.insert("unresolved-instruction");
        Queue.push_back(cast<Value>(Use));
      } else {
        Result.UseKinds.insert("unresolved-user");
      }
    }
  }
  if (Steps >= 10000) {
    Result.UseKinds.insert("walk-limit");
  }
  if (!Result.ResultUsed) {
    Result.UseKinds.insert("ignored");
  }

  std::deque<Value *> ExactQueue;
  std::unordered_set<const Value *> ExactVisited;
  ExactQueue.push_back(&Call);
  bool Exact = true;
  bool SawReturn = false;
  unsigned ExactSteps = 0;
  while (!ExactQueue.empty() && ExactSteps++ < 10000) {
    Value *Current = ExactQueue.front();
    ExactQueue.pop_front();
    if (!ExactVisited.insert(Current).second) {
      continue;
    }
    bool SawNonDebugUse = false;
    for (User *Use : Current->users()) {
      if (isDebugUser(Use)) {
        continue;
      }
      SawNonDebugUse = true;
      if (auto *Return = dyn_cast<ReturnInst>(Use)) {
        if (Return->getReturnValue() == Current) {
          SawReturn = true;
          continue;
        }
      }
      if (auto *SignExtend = dyn_cast<SExtInst>(Use)) {
        if (SignExtend->getOperand(0) == Current) {
          ExactQueue.push_back(SignExtend);
          continue;
        }
      }
      Exact = false;
    }
    if (!SawNonDebugUse) {
      Exact = false;
    }
  }
  if (ExactSteps >= 10000) {
    Exact = false;
  }
  Result.MustReturnExact = Exact && SawReturn;
  if (Result.MustReturnExact) {
    Result.UseKinds.insert("must-return-exact");
  }
  Result.MustReturnNegativeOnError =
      mustReturnNegativeUnder(Call, AbstractValue::Negative);
  Result.MustReturnNegativeOnFalse =
      mustReturnNegativeUnder(Call, AbstractValue::Zero);
  Result.MustReturnNegativeOnTrue =
      mustReturnNegativeUnder(Call, AbstractValue::Positive);
  bool IntegerSuccessTypes =
      Call.getType()->isIntegerTy() &&
      Call.getFunction()->getReturnType()->isIntegerTy();
  Result.MustReturnNonnegativeOnZero =
      IntegerSuccessTypes &&
      mustReturnNonnegativeUnder(Call, AbstractValue::Zero);
  Result.MustReturnNonnegativeOnPositive =
      IntegerSuccessTypes &&
      mustReturnNonnegativeUnder(Call, AbstractValue::Positive);
  Result.MustPreserveNonnegativeSuccess =
      Result.MustReturnNonnegativeOnZero &&
      Result.MustReturnNonnegativeOnPositive;
  bool PointerSuccessTypes =
      Call.getType()->isPointerTy() &&
      Call.getFunction()->getReturnType()->isPointerTy();
  Result.MustReturnValidPointerOnValidPointer =
      PointerSuccessTypes &&
      mustReturnValidPointerUnder(Call, AbstractValue::ValidPointer);
  Result.MustPreserveValidPointerSuccess =
      Result.MustReturnValidPointerOnValidPointer;
  if (Result.MustReturnNegativeOnError) {
    Result.UseKinds.insert("must-return-negative-on-error");
  }
  if (Result.MustReturnNegativeOnFalse) {
    Result.UseKinds.insert("must-return-negative-on-false");
  }
  if (Result.MustReturnNegativeOnTrue) {
    Result.UseKinds.insert("must-return-negative-on-true");
  }
  if (Result.MustReturnNonnegativeOnZero) {
    Result.UseKinds.insert("must-return-nonnegative-on-zero");
  }
  if (Result.MustReturnNonnegativeOnPositive) {
    Result.UseKinds.insert("must-return-nonnegative-on-positive");
  }
  if (Result.MustPreserveNonnegativeSuccess) {
    Result.UseKinds.insert("must-preserve-nonnegative-success");
  }
  if (Result.MustReturnValidPointerOnValidPointer) {
    Result.UseKinds.insert("must-return-valid-pointer-on-valid-pointer");
  }
  if (Result.MustPreserveValidPointerSuccess) {
    Result.UseKinds.insert("must-preserve-valid-pointer-success");
  }
  return Result;
}

json::Array stringsJSON(const std::set<std::string> &Values) {
  json::Array Result;
  for (const std::string &Value : Values) {
    Result.push_back(Value);
  }
  return Result;
}

json::Object factJSON(const Fact &Result) {
  StringRef Verification = "ssa_use_unresolved";
  if (!Result.ResultUsed) {
    Verification = "ignored";
  } else if (Result.MustReturnExact) {
    Verification = "must_return_exact";
  } else if (Result.MustReturnNegativeOnError ||
             Result.MustReturnNegativeOnFalse ||
             Result.MustReturnNegativeOnTrue) {
    Verification = "must_return_negative";
  } else if (Result.MustPreserveNonnegativeSuccess ||
             Result.MustPreserveValidPointerSuccess) {
    Verification = "must_preserve_success";
  } else if (Result.ControlsBranch && Result.ReachesReturn) {
    Verification = "controls_branch_and_reaches_return";
  } else if (Result.ControlsBranch) {
    Verification = "controls_branch";
  } else if (Result.ReachesReturn) {
    Verification = "reaches_return";
  }
  return json::Object{
      {"kind", Result.Kind},
      {"hook", Result.Hook},
      {"callee", Result.Callee},
      {"function", Result.Function},
      {"source_function", Result.SourceFunction},
      {"source_file", Result.SourceFile},
      {"source_line", static_cast<int64_t>(Result.SourceLine)},
      {"source_column", static_cast<int64_t>(Result.SourceColumn)},
      {"inlined_at_functions", [&]() {
         json::Array Values;
         for (const std::string &Value : Result.InlinedAtFunctions) {
           Values.push_back(Value);
         }
         return Values;
       }()},
      {"module", Result.Module},
      {"result_used", Result.ResultUsed},
      {"controls_branch", Result.ControlsBranch},
      {"reaches_return", Result.ReachesReturn},
      {"must_return_exact", Result.MustReturnExact},
      {"must_return_negative_on_error",
       Result.MustReturnNegativeOnError},
      {"must_return_negative_on_false",
       Result.MustReturnNegativeOnFalse},
      {"must_return_negative_on_true",
       Result.MustReturnNegativeOnTrue},
      {"must_return_nonnegative_on_zero",
       Result.MustReturnNonnegativeOnZero},
      {"must_return_nonnegative_on_positive",
       Result.MustReturnNonnegativeOnPositive},
      {"must_preserve_nonnegative_success",
       Result.MustPreserveNonnegativeSuccess},
      {"must_return_valid_pointer_on_valid_pointer",
       Result.MustReturnValidPointerOnValidPointer},
      {"must_preserve_valid_pointer_success",
       Result.MustPreserveValidPointerSuccess},
      {"function_has_return", Result.FunctionHasReturn},
      {"function_must_return_nonnegative",
       Result.FunctionMustReturnNonnegative},
      {"function_must_return_nonpositive",
       Result.FunctionMustReturnNonpositive},
      {"function_must_return_nonnull",
       Result.FunctionMustReturnNonNull},
      {"function_must_return_valid_pointer",
       Result.FunctionMustReturnValidPointer},
      {"function_must_return_true", Result.FunctionMustReturnTrue},
      {"function_preserved_pointee_arguments", [&]() {
         json::Array Values;
         for (unsigned Value :
              Result.FunctionPreservedPointeeArguments) {
           Values.push_back(static_cast<int64_t>(Value));
         }
         return Values;
       }()},
      {"does_not_access_memory", Result.DoesNotAccessMemory},
      {"only_reads_memory", Result.OnlyReadsMemory},
      {"use_kinds", stringsJSON(Result.UseKinds)},
      {"verification", Verification},
  };
}

} // namespace

int main(int argc, const char **argv) {
  Options ToolOptions;
  if (!parseOptions(argc, argv, ToolOptions)) {
    return 2;
  }

  LLVMContext Context;
  SMDiagnostic Diagnostic;
  std::unique_ptr<Module> Input =
      parseIRFile(ToolOptions.Input, Diagnostic, Context);
  if (!Input) {
    Diagnostic.print(argv[0], errs());
    return 1;
  }

  std::error_code OutputError;
  raw_fd_ostream Output(ToolOptions.Output, OutputError, sys::fs::OF_Text);
  if (OutputError) {
    errs() << "open output: " << OutputError.message() << "\n";
    return 1;
  }

  StringRef ModuleName = Input->getSourceFileName();
  PointeePreservationMap PointeePreservation =
      computePointeePreservation(*Input);
  NonpositiveReturnMap NonpositiveReturns =
      computeNonpositiveReturns(*Input);
  for (Function &FunctionValue : *Input) {
    if (FunctionValue.isDeclaration()) {
      continue;
    }
    Fact FunctionSummary =
        analyzeFunctionReturns(
            FunctionValue, ModuleName, PointeePreservation,
            NonpositiveReturns);
    Output << formatv("{0}\n", json::Value(factJSON(FunctionSummary)));
    for (BasicBlock &Block : FunctionValue) {
      for (Instruction &InstructionValue : Block) {
        auto *Call = dyn_cast<CallBase>(&InstructionValue);
        if (!Call) {
          continue;
        }
        Function *Callee = directCallee(*Call);
        if (!Callee || Callee->isIntrinsic() ||
            Callee->getName().startswith("llvm.")) {
          continue;
        }
        Fact Result = analyzeCall(*Call, Callee->getName(), ModuleName);
        Output << formatv("{0}\n", json::Value(factJSON(Result)));
      }
    }
  }
  Output.flush();
  return 0;
}
