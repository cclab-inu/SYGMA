#include "clang/AST/Decl.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ODRHash.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/CFG.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace clang;
using namespace clang::tooling;

namespace {

struct Options {
  std::string CompileDB;
  std::string FilesFrom;
  std::string KernelRoot;
  std::string Output;
};

struct Event {
  const Stmt *Node = nullptr;
  std::string Key;
  std::string CallSiteID;
  std::string Name;
  std::string Expression;
  bool Direct = false;
  bool LSM = false;
  bool Signal = false;
  unsigned Line = 0;
  unsigned Column = 0;
};

struct CallTarget {
  std::string Name;
  std::string File;
  std::string ReturnType;
  std::string ReturnTypeCanonical;
  std::string ReturnTypeClass;
  bool ReturnTypeSigned = false;
  unsigned ReturnTypeBits = 0;
  bool Static = false;
  bool Inline = false;
  std::string SemanticHash;
  unsigned Line = 0;
};

struct IndirectTarget {
  std::string Expression;
  std::string StructType;
  std::string Field;
  std::string ReturnType;
  std::string ReturnTypeCanonical;
  std::string ReturnTypeClass;
  bool ReturnTypeSigned = false;
  unsigned ReturnTypeBits = 0;
};

struct CallbackArgument {
  unsigned Index = 0;
  bool Complete = false;
  bool MayBeNull = false;
  std::vector<CallTarget> Targets;
};

struct CallSite {
  std::string ID;
  bool Direct = false;
  bool Reachable = false;
  unsigned BlockID = 0;
  bool HasBlock = false;
  std::string Name;
  std::string Expression;
  std::string ResultUse;
  std::string ResultVariable;
  std::string ReturnType;
  std::string ReturnTypeCanonical;
  std::string ReturnTypeClass;
  bool ReturnTypeSigned = false;
  unsigned ReturnTypeBits = 0;
  std::vector<std::string> Arguments;
  std::vector<std::string> ArgumentConstants;
  std::vector<CallbackArgument> CallbackArguments;
  unsigned Line = 0;
  unsigned Column = 0;
  unsigned SpellingLine = 0;
  unsigned SpellingColumn = 0;
  bool MacroExpansion = false;
};

struct ValueWrite {
  std::string Target;
  std::string Expression;
  std::string ExpressionExpanded;
  std::string Kind;
  std::string CallSiteID;
  bool SourceDefinitelyNonnegative = false;
  bool SourceDefinitelyValidPointer = false;
  std::string SourceTypeClass;
  bool SourceTypeSigned = false;
  unsigned SourceTypeBits = 0;
  std::string TargetTypeClass;
  bool TargetTypeSigned = false;
  unsigned TargetTypeBits = 0;
};

struct PointeeWrite {
  std::string Parameter;
  std::string Expression;
  std::string Kind;
  bool SourceDefinitelyNonnegative = false;
  bool SourceDefinitelyValidPointer = false;
  std::string SourceTypeClass;
  bool SourceTypeSigned = false;
  unsigned SourceTypeBits = 0;
  std::string TargetTypeClass;
  bool TargetTypeSigned = false;
  unsigned TargetTypeBits = 0;
};

struct BlockRecord {
  unsigned ID = 0;
  std::vector<unsigned> Successors;
  std::vector<std::string> SuccessorBranches;
  std::vector<unsigned> SuccessSuccessors;
  std::vector<std::string> SuccessSuccessorBranches;
  std::string TerminatorCondition;
  std::string ReturnExpression;
  std::string ReturnExpressionExpanded;
  bool ReturnDefinitelyNonnegative = false;
  bool ReturnDefinitelyValidPointer = false;
  std::vector<std::string> Calls;
  std::vector<std::string> IndirectCalls;
  std::vector<std::string> LSMHooks;
  std::vector<std::string> SignalChecks;
  std::vector<std::string> CallSiteIDs;
  std::vector<ValueWrite> ValueWrites;
  std::vector<PointeeWrite> PointeeWrites;
  bool PotentialSuccessExit = false;
  bool FailureOnlyExit = false;
};

struct FunctionRecord {
  std::string Name;
  std::string File;
  std::string TranslationUnit;
  std::string ReturnType;
  std::string ReturnTypeCanonical;
  std::string ReturnTypeClass;
  bool ReturnTypeSigned = false;
  unsigned ReturnTypeBits = 0;
  bool Static = false;
  bool Inline = false;
  std::string SemanticHash;
  unsigned Line = 0;
  unsigned Column = 0;
  std::vector<std::string> Parameters;
  std::map<std::string, std::string> StructVariables;
  std::string Body;
  std::vector<std::string> DirectCalls;
  std::vector<std::string> IndirectCalls;
  std::vector<std::string> LSMHooks;
  std::vector<std::string> SignalChecks;
  std::vector<CallTarget> CallTargets;
  std::vector<IndirectTarget> IndirectTargets;
  std::vector<CallSite> CallSites;
  std::vector<std::string> ReachableCalls;
  std::vector<std::string> ReachableIndirectCalls;
  std::vector<std::string> ReachableLSMHooks;
  std::vector<std::string> ReachableSignalChecks;
  std::vector<std::string> MustSuccessCalls;
  std::vector<std::string> MustSuccessIndirectCalls;
  std::vector<std::string> MustSuccessLSMHooks;
  std::vector<std::string> MustSuccessSignalChecks;
  std::vector<std::string> ReachableCallSiteIDs;
  std::vector<std::string> MustSuccessCallSiteIDs;
  std::vector<std::string> UnplacedCallSiteIDs;
  std::vector<std::string> UnplacedEvents;
  std::vector<std::string> EscapedVariables;
  std::vector<BlockRecord> Blocks;
  unsigned CFGEntry = 0;
  unsigned CFGExit = 0;
  bool CFGComplete = false;
  bool HasPotentialSuccessExit = false;
  bool UsedKernelErrnoGuards = false;
  std::string CFGFailure;
};

struct OperationFieldTarget {
  std::string Field;
  std::string Function;
  std::string File;
};

struct OperationTableRecord {
  std::string StructType;
  std::string Table;
  std::string File;
  bool Const = false;
  bool Complete = false;
  std::vector<OperationFieldTarget> FieldTargets;
  std::vector<std::string> NullFields;
  std::vector<std::string> UnknownFields;
};

std::string canonicalPath(llvm::StringRef Path) {
  if (Path.empty()) {
    return {};
  }
  llvm::SmallString<256> Result;
  if (!llvm::sys::fs::real_path(Path, Result, true)) {
    return Result.str().str();
  }
  llvm::SmallString<256> Absolute(Path);
  if (!llvm::sys::path::is_absolute(Absolute)) {
    llvm::sys::fs::make_absolute(Absolute);
  }
  llvm::sys::path::remove_dots(Absolute, true);
  return Absolute.str().str();
}

bool pathWithin(llvm::StringRef Root, llvm::StringRef Path) {
  if (Root.empty() || Path.empty()) {
    return false;
  }
  llvm::SmallString<256> RootWithSlash(Root);
  llvm::sys::path::append(RootWithSlash, "");
  if (!RootWithSlash.endswith(llvm::sys::path::get_separator())) {
    RootWithSlash += llvm::sys::path::get_separator();
  }
  return Path == Root || Path.startswith(RootWithSlash);
}

template <typename T>
void appendUnique(std::vector<T> &Values, const T &Value) {
  if (std::find(Values.begin(), Values.end(), Value) == Values.end()) {
    Values.push_back(Value);
  }
}

void appendCallTarget(std::vector<CallTarget> &Targets,
                      const CallTarget &Target) {
  for (const CallTarget &Existing : Targets) {
    if (Existing.Name == Target.Name && Existing.File == Target.File &&
        Existing.Static == Target.Static &&
        Existing.Inline == Target.Inline &&
        Existing.SemanticHash == Target.SemanticHash &&
        Existing.Line == Target.Line) {
      return;
    }
  }
  Targets.push_back(Target);
}

std::string functionSemanticHash(const FunctionDecl *Function) {
  if (!Function) {
    return {};
  }
  ODRHash Hash;
  Hash.AddFunctionDecl(Function);
  return std::to_string(Hash.CalculateHash());
}

void appendIndirectTarget(std::vector<IndirectTarget> &Targets,
                          const IndirectTarget &Target) {
  for (const IndirectTarget &Existing : Targets) {
    if (Existing.Expression == Target.Expression &&
        Existing.StructType == Target.StructType &&
        Existing.Field == Target.Field &&
        Existing.ReturnType == Target.ReturnType) {
      return;
    }
  }
  Targets.push_back(Target);
}

void appendCallSite(std::vector<CallSite> &Sites, const CallSite &Site) {
  for (const CallSite &Existing : Sites) {
    if (Existing.ID == Site.ID) {
      return;
    }
  }
  Sites.push_back(Site);
}

const Expr *stripInitializerExpression(const Expr *Expression);
const FunctionDecl *initializerFunction(const Expr *Expression);
bool collectCallbackFunctions(const Expr *Expression, ASTContext &Context,
                              std::vector<const FunctionDecl *> &Functions,
                              bool &MayBeNull);

std::string sourceText(const SourceManager &SM, const LangOptions &LangOpts,
                       SourceRange Range) {
  if (Range.isInvalid()) {
    return {};
  }
  CharSourceRange TokenRange = CharSourceRange::getTokenRange(Range);
  CharSourceRange FileRange =
      Lexer::makeFileCharRange(TokenRange, SM, LangOpts);
  if (FileRange.isInvalid()) {
    return {};
  }
  bool Invalid = false;
  llvm::StringRef Text =
      Lexer::getSourceText(FileRange, SM, LangOpts, &Invalid);
  if (Invalid) {
    return {};
  }
  return Text.str();
}

std::string locationFile(const SourceManager &SM, SourceLocation Location) {
  if (Location.isInvalid()) {
    return {};
  }
  SourceLocation Expansion = SM.getExpansionLoc(Location);
  PresumedLoc Presumed = SM.getPresumedLoc(Expansion);
  if (Presumed.isInvalid()) {
    return {};
  }
  return canonicalPath(Presumed.getFilename());
}

bool isSignalCheckName(llvm::StringRef Name) {
  return Name == "fatal_signal_pending" || Name == "signal_pending" ||
         Name == "__fatal_signal_pending" || Name == "task_sigpending" ||
         Name == "signal_group_exit" || Name == "signal_pending_state";
}

std::string diagnosticEventKey(const Event &Item) {
  if (Item.Direct) {
    return "call:" + Item.Name;
  }
  if (!Item.Expression.empty()) {
    return "indirect:" + Item.Expression;
  }
  if (Item.Signal) {
    return "signal:" + Item.Name;
  }
  return Item.Key;
}

std::string recordTypeName(QualType Type) {
  Type = Type.getNonReferenceType();
  while (!Type.isNull()) {
    if (Type->isPointerType()) {
      Type = Type->getPointeeType();
      continue;
    }
    if (const auto *Array = dyn_cast<ArrayType>(Type.getTypePtr())) {
      Type = Array->getElementType();
      continue;
    }
    break;
  }
  if (Type.isNull()) {
    return {};
  }
  QualType Canonical = Type.getCanonicalType().getUnqualifiedType();
  if (const auto *Record = Canonical->getAs<RecordType>()) {
    return Record->getDecl()->getNameAsString();
  }
  return {};
}

struct TypeMetadata {
  std::string Spelling;
  std::string Canonical;
  std::string Class;
  bool Signed = false;
  unsigned Bits = 0;
};

TypeMetadata describeType(QualType Type, ASTContext &Context) {
  TypeMetadata Result;
  if (Type.isNull()) {
    Result.Class = "other";
    return Result;
  }

  PrintingPolicy Policy(Context.getLangOpts());
  Policy.SuppressTagKeyword = false;
  Result.Spelling = Type.getAsString(Policy);

  QualType Canonical = Type.getCanonicalType().getUnqualifiedType();
  Result.Canonical = Canonical.getAsString(Policy);
  if (Canonical->isVoidType()) {
    Result.Class = "void";
  } else if (Canonical->isBooleanType()) {
    Result.Class = "bool";
    Result.Bits = Context.getTypeSize(Canonical);
  } else if (Canonical->isPointerType() ||
             Canonical->isBlockPointerType() ||
             Canonical->isMemberPointerType()) {
    Result.Class = "pointer";
    Result.Bits = Context.getTypeSize(Canonical);
  } else if (Canonical->isSignedIntegerOrEnumerationType()) {
    Result.Class = "signed_integer";
    Result.Signed = true;
    Result.Bits = Context.getTypeSize(Canonical);
  } else if (Canonical->isUnsignedIntegerOrEnumerationType()) {
    Result.Class = "unsigned_integer";
    Result.Bits = Context.getTypeSize(Canonical);
  } else if (Canonical->isRecordType()) {
    Result.Class = "record";
  } else {
    Result.Class = "other";
  }
  return Result;
}

const Expr *terminalValueExpression(const Expr *Expression,
                                    unsigned Depth = 0) {
  if (!Expression || Depth > 16) {
    return nullptr;
  }
  if (const auto *Parenthesized = dyn_cast<ParenExpr>(Expression)) {
    return terminalValueExpression(
        Parenthesized->getSubExpr(), Depth + 1);
  }
  if (const auto *Cast = dyn_cast<ImplicitCastExpr>(Expression)) {
    return terminalValueExpression(Cast->getSubExpr(), Depth + 1);
  }
  if (const auto *Cleanup = dyn_cast<ExprWithCleanups>(Expression)) {
    return terminalValueExpression(Cleanup->getSubExpr(), Depth + 1);
  }
  if (const auto *Binary = dyn_cast<BinaryOperator>(Expression)) {
    if (Binary->getOpcode() == BO_Comma) {
      return terminalValueExpression(Binary->getRHS(), Depth + 1);
    }
  }
  if (const auto *StatementExpression = dyn_cast<StmtExpr>(Expression)) {
    const CompoundStmt *Compound = StatementExpression->getSubStmt();
    if (!Compound) {
      return nullptr;
    }
    for (auto Iterator = Compound->body_rbegin();
         Iterator != Compound->body_rend(); ++Iterator) {
      if (const auto *LastExpression = dyn_cast<Expr>(*Iterator)) {
        return terminalValueExpression(
            LastExpression, Depth + 1);
      }
    }
    return nullptr;
  }
  return Expression;
}

bool expressionDefinitelyNonnegative(const Expr *Expression,
                                     ASTContext &Context,
                                     unsigned Depth = 0) {
  if (!Expression || Depth > 16) {
    return false;
  }
  if (const auto *Parenthesized = dyn_cast<ParenExpr>(Expression)) {
    return expressionDefinitelyNonnegative(
        Parenthesized->getSubExpr(), Context, Depth + 1);
  }

  TypeMetadata Type = describeType(Expression->getType(), Context);
  if (Type.Class == "unsigned_integer" || Type.Class == "bool") {
    return true;
  }
  if (const Expr *Terminal = terminalValueExpression(Expression)) {
    TypeMetadata TerminalType =
        describeType(Terminal->getType(), Context);
    if ((TerminalType.Class == "unsigned_integer" ||
         TerminalType.Class == "bool") &&
        Type.Class == "signed_integer" &&
        Type.Bits > TerminalType.Bits) {
      return true;
    }
  }

  Expr::EvalResult Constant;
  if (Expression->EvaluateAsInt(Constant, Context)) {
    const llvm::APSInt &Value = Constant.Val.getInt();
    return !Value.isSigned() || !Value.isNegative();
  }

  if (const auto *Cast = dyn_cast<ImplicitCastExpr>(Expression)) {
    const Expr *Operand = Cast->getSubExpr();
    TypeMetadata OperandType = describeType(Operand->getType(), Context);
    if (Type.Class == "signed_integer" &&
        (OperandType.Class == "signed_integer" ||
         OperandType.Class == "unsigned_integer" ||
         OperandType.Class == "bool")) {
      if (OperandType.Class == "unsigned_integer" ||
          OperandType.Class == "bool") {
        return Type.Bits > OperandType.Bits;
      }
      if (Type.Bits < OperandType.Bits) {
        return false;
      }
    }
    return expressionDefinitelyNonnegative(Operand, Context, Depth + 1);
  }
  if (const auto *Cast = dyn_cast<ExplicitCastExpr>(Expression)) {
    const Expr *Operand = Cast->getSubExpr();
    TypeMetadata OperandType = describeType(Operand->getType(), Context);
    if ((OperandType.Class == "unsigned_integer" ||
         OperandType.Class == "bool") &&
        Type.Class == "signed_integer" && Type.Bits > OperandType.Bits) {
      return true;
    }
    return Type.Class == "unsigned_integer";
  }
  if (const auto *Conditional = dyn_cast<ConditionalOperator>(Expression)) {
    return expressionDefinitelyNonnegative(
               Conditional->getTrueExpr(), Context, Depth + 1) &&
           expressionDefinitelyNonnegative(
               Conditional->getFalseExpr(), Context, Depth + 1);
  }
  if (const auto *Binary = dyn_cast<BinaryOperator>(Expression)) {
    if (Binary->isComparisonOp()) {
      return true;
    }
    if (Binary->getOpcode() == BO_And) {
      auto CannotSetSignBit = [&](const Expr *Operand) {
        Expr::EvalResult Evaluated;
        if (!Operand->EvaluateAsInt(Evaluated, Context) ||
            Type.Class != "signed_integer" || Type.Bits == 0) {
          return false;
        }
        const llvm::APSInt &Value = Evaluated.Val.getInt();
        if (Value.isSigned() && Value.isNegative()) {
          return false;
        }
        llvm::APInt Bits = Value;
        Bits = Bits.zextOrTrunc(Type.Bits);
        return !Bits[Type.Bits - 1];
      };
      return CannotSetSignBit(Binary->getLHS()) ||
             CannotSetSignBit(Binary->getRHS());
    }
  }
  if (const auto *Unary = dyn_cast<UnaryOperator>(Expression)) {
    if (Unary->getOpcode() == UO_LNot) {
      return true;
    }
  }
  if (const auto *StatementExpression = dyn_cast<StmtExpr>(Expression)) {
    const CompoundStmt *Compound = StatementExpression->getSubStmt();
    if (Compound) {
      for (auto Iterator = Compound->body_rbegin();
           Iterator != Compound->body_rend(); ++Iterator) {
        if (const auto *LastExpression = dyn_cast<Expr>(*Iterator)) {
          return expressionDefinitelyNonnegative(
              LastExpression, Context, Depth + 1);
        }
      }
    }
  }
  return false;
}

bool expressionDefinitelyValidPointer(const Expr *Expression) {
  if (!Expression) {
    return false;
  }
  const Expr *Value = Expression->IgnoreParenImpCasts();
  if (isa<StringLiteral>(Value)) {
    return true;
  }
  if (const auto *Reference = dyn_cast<DeclRefExpr>(Value)) {
    const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl());
    if (Variable && Variable->getType()->isArrayType()) {
      return true;
    }
  }
  const auto *Address = dyn_cast<UnaryOperator>(Value);
  if (!Address || Address->getOpcode() != UO_AddrOf) {
    return false;
  }
  const Expr *Operand =
      Address->getSubExpr()->IgnoreParenImpCasts();
  return !isa<UnaryOperator>(Operand) ||
         cast<UnaryOperator>(Operand)->getOpcode() != UO_Deref;
}

bool containsStmt(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target) {
    return false;
  }
  if (Root == Target) {
    return true;
  }
  for (const Stmt *Child : Root->children()) {
    if (containsStmt(Child, Target)) {
      return true;
    }
  }
  return false;
}

unsigned stmtNodeCount(const Stmt *Root) {
  if (!Root) {
    return 0;
  }
  unsigned Result = 1;
  for (const Stmt *Child : Root->children()) {
    Result += stmtNodeCount(Child);
  }
  return Result;
}

bool expansionRangeOffsets(const Stmt *Node, const SourceManager &SM,
                           const LangOptions &LangOpts, FileID &File,
                           unsigned &Begin, unsigned &End) {
  if (!Node) {
    return false;
  }
  SourceRange Range = Node->getSourceRange();
  SourceLocation BeginLocation = SM.getExpansionLoc(Range.getBegin());
  SourceLocation EndLocation = SM.getExpansionLoc(Range.getEnd());
  if (BeginLocation.isInvalid() || EndLocation.isInvalid()) {
    return false;
  }
  FileID BeginFile = SM.getFileID(BeginLocation);
  FileID EndFile = SM.getFileID(EndLocation);
  if (BeginFile.isInvalid() || BeginFile != EndFile) {
    return false;
  }
  SourceLocation TokenEnd =
      Lexer::getLocForEndOfToken(EndLocation, 0, SM, LangOpts);
  if (TokenEnd.isInvalid() || SM.getFileID(TokenEnd) != BeginFile) {
    TokenEnd = EndLocation.getLocWithOffset(1);
  }
  File = BeginFile;
  Begin = SM.getFileOffset(BeginLocation);
  End = SM.getFileOffset(TokenEnd);
  return End >= Begin;
}

bool sourceRangeContains(const Stmt *Container, const Stmt *Contained,
                         const SourceManager &SM,
                         const LangOptions &LangOpts) {
  FileID ContainerFile;
  FileID ContainedFile;
  unsigned ContainerBegin = 0;
  unsigned ContainerEnd = 0;
  unsigned ContainedBegin = 0;
  unsigned ContainedEnd = 0;
  return expansionRangeOffsets(Container, SM, LangOpts, ContainerFile,
                               ContainerBegin, ContainerEnd) &&
         expansionRangeOffsets(Contained, SM, LangOpts, ContainedFile,
                               ContainedBegin, ContainedEnd) &&
         ContainerFile == ContainedFile && ContainerBegin <= ContainedBegin &&
         ContainerEnd >= ContainedEnd;
}

std::string classifyCallResultUse(const CallExpr *Call, ASTContext &Context) {
  const Stmt *Current = Call;
  for (unsigned Depth = 0; Current && Depth < 32; ++Depth) {
    DynTypedNodeList Parents = Context.getParents(*Current);
    if (Parents.size() != 1) {
      return "unknown";
    }
    const DynTypedNode &Parent = Parents[0];
    if (Parent.get<ReturnStmt>()) {
      return "returned";
    }
    if (Parent.get<VarDecl>()) {
      return "assigned";
    }
    if (const auto *ParentCall = Parent.get<CallExpr>()) {
      if (ParentCall != Call) {
        return "argument";
      }
    }
    const Stmt *ParentStmt = Parent.get<Stmt>();
    if (!ParentStmt) {
      return "unknown";
    }
    if (const auto *Binary = dyn_cast<BinaryOperator>(ParentStmt)) {
      if (Binary->isAssignmentOp() &&
          containsStmt(Binary->getRHS(), Current)) {
        return "assigned";
      }
      if (Binary->getOpcode() == BO_Comma &&
          containsStmt(Binary->getLHS(), Current)) {
        return "discarded";
      }
      Current = ParentStmt;
      continue;
    }
    if (const auto *If = dyn_cast<IfStmt>(ParentStmt)) {
      if (containsStmt(If->getCond(), Current)) {
        return "condition";
      }
      return "discarded";
    }
    if (const auto *While = dyn_cast<WhileStmt>(ParentStmt)) {
      if (containsStmt(While->getCond(), Current)) {
        return "condition";
      }
      return "discarded";
    }
    if (const auto *Do = dyn_cast<DoStmt>(ParentStmt)) {
      if (containsStmt(Do->getCond(), Current)) {
        return "condition";
      }
      return "discarded";
    }
    if (const auto *For = dyn_cast<ForStmt>(ParentStmt)) {
      if (containsStmt(For->getCond(), Current)) {
        return "condition";
      }
      if (containsStmt(For->getInit(), Current)) {
        return "assigned";
      }
      return "discarded";
    }
    if (const auto *Switch = dyn_cast<SwitchStmt>(ParentStmt)) {
      if (containsStmt(Switch->getCond(), Current)) {
        return "condition";
      }
      return "discarded";
    }
    if (const auto *Compound = dyn_cast<CompoundStmt>(ParentStmt)) {
      DynTypedNodeList Grandparents = Context.getParents(*Compound);
      if (Grandparents.size() == 1 && Grandparents[0].get<StmtExpr>() &&
          !Compound->body_empty() &&
          containsStmt(Compound->body_back(), Current)) {
        Current = Grandparents[0].get<StmtExpr>();
        continue;
      }
      return "discarded";
    }
    if (isa<Expr>(ParentStmt)) {
      Current = ParentStmt;
      continue;
    }
    return "unknown";
  }
  return "unknown";
}

const DeclRefExpr *declRefTarget(const Expr *Expression) {
  if (!Expression) {
    return nullptr;
  }
  return dyn_cast<DeclRefExpr>(Expression->IgnoreParenImpCasts());
}

const DeclRefExpr *arrowMemberBaseTarget(const Expr *Expression) {
  if (!Expression) {
    return nullptr;
  }
  const Expr *Current = Expression->IgnoreParenImpCasts();
  bool SawArrow = false;
  while (const auto *Member = dyn_cast<MemberExpr>(Current)) {
    SawArrow = SawArrow || Member->isArrow();
    Current = Member->getBase()->IgnoreParenImpCasts();
  }
  if (!SawArrow) {
    return nullptr;
  }
  return dyn_cast<DeclRefExpr>(Current);
}

std::string callResultVariable(const CallExpr *Call, ASTContext &Context) {
  const Stmt *Current = Call;
  const ValueDecl *RequiredTarget = nullptr;
  for (unsigned Depth = 0; Current && Depth < 32; ++Depth) {
    DynTypedNodeList Parents = Context.getParents(*Current);
    if (Parents.size() != 1) {
      return {};
    }
    const DynTypedNode &Parent = Parents[0];
    if (const auto *Variable = Parent.get<VarDecl>()) {
      return Variable->getNameAsString();
    }
    const Stmt *ParentStmt = Parent.get<Stmt>();
    if (!ParentStmt) {
      return {};
    }
    if (const auto *Binary = dyn_cast<BinaryOperator>(ParentStmt)) {
      if (Binary->getOpcode() == BO_Assign &&
          containsStmt(Binary->getRHS(), Current)) {
        const DeclRefExpr *Target = declRefTarget(Binary->getLHS());
        if (Target) {
          if (RequiredTarget && Target->getDecl() != RequiredTarget) {
            return {};
          }
          return Target->getDecl()->getNameAsString();
        }
        const DeclRefExpr *MemberBase =
            arrowMemberBaseTarget(Binary->getLHS());
        if (!MemberBase ||
            (RequiredTarget && MemberBase->getDecl() != RequiredTarget)) {
          return {};
        }
        RequiredTarget = MemberBase->getDecl();
        Current = ParentStmt;
        continue;
      }
    }
    if (!isa<Expr>(ParentStmt)) {
      return {};
    }
    Current = ParentStmt;
  }
  return {};
}

class BodyVisitor : public RecursiveASTVisitor<BodyVisitor> {
public:
  BodyVisitor(ASTContext &Context, FunctionRecord &Record)
      : Context(Context), Record(Record), SM(Context.getSourceManager()),
        LangOpts(Context.getLangOpts()) {}

  bool VisitParmVarDecl(ParmVarDecl *Decl) {
    addParameter(Decl);
    return true;
  }

  bool VisitVarDecl(VarDecl *Decl) {
    addStructVariable(Decl);
    return true;
  }

  bool VisitCallExpr(CallExpr *Call) {
    Event Item;
    CallSite Site;
    Item.Node = Call;
    Site.ID = "callsite:" + std::to_string(++CallSiteOrdinal);
    Item.CallSiteID = Site.ID;
    Item.Key = Site.ID;
    PresumedLoc Location = SM.getPresumedLoc(SM.getExpansionLoc(Call->getExprLoc()));
    if (Location.isValid()) {
      Item.Line = Location.getLine();
      Item.Column = Location.getColumn();
      Site.Line = Item.Line;
      Site.Column = Item.Column;
    }
    SourceLocation SpellingLocation = SM.getSpellingLoc(Call->getExprLoc());
    PresumedLoc Spelling = SM.getPresumedLoc(SpellingLocation);
    if (Spelling.isValid()) {
      Site.SpellingLine = Spelling.getLine();
      Site.SpellingColumn = Spelling.getColumn();
    }
    Site.MacroExpansion = Call->getExprLoc().isMacroID();
    PrintingPolicy Policy(Context.getLangOpts());
    Policy.SuppressTagKeyword = false;
    TypeMetadata CallType = describeType(Call->getType(), Context);
    Site.ReturnType = CallType.Spelling;
    Site.ReturnTypeCanonical = CallType.Canonical;
    Site.ReturnTypeClass = CallType.Class;
    Site.ReturnTypeSigned = CallType.Signed;
    Site.ReturnTypeBits = CallType.Bits;
    Site.ResultUse = classifyCallResultUse(Call, Context);
    Site.ResultVariable = callResultVariable(Call, Context);
    for (unsigned ArgumentIndex = 0;
         ArgumentIndex < Call->getNumArgs(); ++ArgumentIndex) {
      const Expr *Argument = Call->getArg(ArgumentIndex);
      std::string Text =
          sourceText(SM, LangOpts, Argument->getSourceRange());
      if (Text.empty()) {
        llvm::raw_string_ostream Stream(Text);
        Argument->printPretty(Stream, nullptr, Policy);
        Stream.flush();
      }
      Site.Arguments.push_back(std::move(Text));
      Expr::EvalResult Result;
      std::string Constant;
      if (Argument->IgnoreParenImpCasts()->EvaluateAsInt(Result, Context)) {
        llvm::SmallString<32> Buffer;
        Result.Val.getInt().toString(Buffer, 10);
        Constant = Buffer.str().str();
      }
      Site.ArgumentConstants.push_back(std::move(Constant));

      std::vector<const FunctionDecl *> Callbacks;
      bool MayBeNull = false;
      if (collectCallbackFunctions(Argument, Context, Callbacks, MayBeNull) &&
          !Callbacks.empty()) {
        CallbackArgument CallbackRecord;
        CallbackRecord.Index = ArgumentIndex;
        CallbackRecord.Complete = true;
        CallbackRecord.MayBeNull = MayBeNull;
        for (const FunctionDecl *Callback : Callbacks) {
          CallTarget Target;
          Target.Name = Callback->getNameAsString();
          Target.File = locationFile(SM, Callback->getLocation());
          TypeMetadata TargetType =
              describeType(Callback->getReturnType(), Context);
          Target.ReturnType = TargetType.Spelling;
          Target.ReturnTypeCanonical = TargetType.Canonical;
          Target.ReturnTypeClass = TargetType.Class;
          Target.ReturnTypeSigned = TargetType.Signed;
          Target.ReturnTypeBits = TargetType.Bits;
          Target.Static = Callback->getStorageClass() == SC_Static ||
                          Callback->getFormalLinkage() == InternalLinkage;
          Target.Inline = Callback->isInlined();
          if (Target.Static || Target.Inline) {
            Target.SemanticHash = functionSemanticHash(Callback);
          }
          PresumedLoc TargetLocation =
              SM.getPresumedLoc(SM.getExpansionLoc(Callback->getLocation()));
          if (TargetLocation.isValid()) {
            Target.Line = TargetLocation.getLine();
          }
          appendCallTarget(CallbackRecord.Targets, Target);
        }
        Site.CallbackArguments.push_back(std::move(CallbackRecord));
      }
    }

    if (const FunctionDecl *Callee = Call->getDirectCallee()) {
      if (Callee->getBuiltinID() != 0) {
        return true;
      }
      if (const FunctionDecl *Definition = Callee->getDefinition()) {
        Callee = Definition;
      }
      Item.Direct = true;
      Item.Name = Callee->getNameAsString();
      Site.Direct = true;
      Site.Name = Item.Name;
      appendUnique(Record.DirectCalls, Item.Name);
      CallTarget Target;
      Target.Name = Item.Name;
      Target.File = locationFile(SM, Callee->getLocation());
      TypeMetadata TargetType = describeType(Callee->getReturnType(), Context);
      Target.ReturnType = TargetType.Spelling;
      Target.ReturnTypeCanonical = TargetType.Canonical;
      Target.ReturnTypeClass = TargetType.Class;
      Target.ReturnTypeSigned = TargetType.Signed;
      Target.ReturnTypeBits = TargetType.Bits;
      Target.Static = Callee->getStorageClass() == SC_Static ||
                      Callee->getFormalLinkage() == InternalLinkage;
      Target.Inline = Callee->isInlined();
      if (Target.Static || Target.Inline) {
        Target.SemanticHash = functionSemanticHash(Callee);
      }
      PresumedLoc TargetLocation =
          SM.getPresumedLoc(SM.getExpansionLoc(Callee->getLocation()));
      if (TargetLocation.isValid()) {
        Target.Line = TargetLocation.getLine();
      }
      appendCallTarget(Record.CallTargets, Target);
      if (llvm::StringRef(Item.Name).startswith("security_")) {
        Item.LSM = true;
        appendUnique(Record.LSMHooks, Item.Name);
      }
      if (isSignalCheckName(Item.Name)) {
        Item.Signal = true;
        appendUnique(Record.SignalChecks, Item.Name);
      }
    } else {
      const Expr *CalleeExpression = Call->getCallee()->IgnoreParenImpCasts();
      Item.Expression =
          sourceText(SM, LangOpts, Call->getCallee()->getSourceRange());
      if (Item.Expression.empty()) {
        Item.Expression = "<indirect-call>";
      }
      appendUnique(Record.IndirectCalls, Item.Expression);
      if (const auto *Member = dyn_cast<MemberExpr>(CalleeExpression)) {
        if (const auto *Field = dyn_cast<FieldDecl>(Member->getMemberDecl())) {
          if (const auto *Owner =
                  dyn_cast<RecordDecl>(Field->getDeclContext())) {
            IndirectTarget Target;
            Target.Expression = Item.Expression;
            Target.StructType = Owner->getNameAsString();
            Target.Field = Field->getNameAsString();
            Target.ReturnType = Site.ReturnType;
            Target.ReturnTypeCanonical = Site.ReturnTypeCanonical;
            Target.ReturnTypeClass = Site.ReturnTypeClass;
            Target.ReturnTypeSigned = Site.ReturnTypeSigned;
            Target.ReturnTypeBits = Site.ReturnTypeBits;
            appendIndirectTarget(Record.IndirectTargets, Target);
          }
        }
      }
      Site.Expression = Item.Expression;
    }
    appendCallSite(Record.CallSites, Site);
    Events.push_back(std::move(Item));
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *Operator) {
    if (!Operator || Operator->getOpcode() != UO_AddrOf) {
      return true;
    }
    const DeclRefExpr *Reference = declRefTarget(Operator->getSubExpr());
    const auto *Variable =
        Reference ? dyn_cast<VarDecl>(Reference->getDecl()) : nullptr;
    if (!Variable ||
        (!Variable->hasLocalStorage() && !isa<ParmVarDecl>(Variable))) {
      return true;
    }
    appendUnique(Record.EscapedVariables, Variable->getNameAsString());
    return true;
  }

  bool VisitGCCAsmStmt(GCCAsmStmt *Statement) {
    if (!Statement) {
      return true;
    }
    for (unsigned Index = 0; Index < Statement->getNumOutputs(); ++Index) {
      const DeclRefExpr *Reference =
          declRefTarget(Statement->getOutputExpr(Index));
      const auto *Variable =
          Reference ? dyn_cast<VarDecl>(Reference->getDecl()) : nullptr;
      if (!Variable ||
          (!Variable->hasLocalStorage() && !isa<ParmVarDecl>(Variable))) {
        continue;
      }
      appendUnique(Record.EscapedVariables, Variable->getNameAsString());
    }
    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *Expr) {
    if (const auto *Function = dyn_cast<FunctionDecl>(Expr->getDecl())) {
      if (Function->getBuiltinID() == 0) {
        if (const FunctionDecl *Definition = Function->getDefinition()) {
          Function = Definition;
        }
        CallTarget Target;
        Target.Name = Function->getNameAsString();
        Target.File = locationFile(SM, Function->getLocation());
        TypeMetadata TargetType =
            describeType(Function->getReturnType(), Context);
        Target.ReturnType = TargetType.Spelling;
        Target.ReturnTypeCanonical = TargetType.Canonical;
        Target.ReturnTypeClass = TargetType.Class;
        Target.ReturnTypeSigned = TargetType.Signed;
        Target.ReturnTypeBits = TargetType.Bits;
        Target.Static = Function->getStorageClass() == SC_Static ||
                        Function->getFormalLinkage() == InternalLinkage;
        Target.Inline = Function->isInlined();
        if (Target.Static || Target.Inline) {
          Target.SemanticHash = functionSemanticHash(Function);
        }
        PresumedLoc TargetLocation =
            SM.getPresumedLoc(SM.getExpansionLoc(Function->getLocation()));
        if (TargetLocation.isValid()) {
          Target.Line = TargetLocation.getLine();
        }
        appendCallTarget(Record.CallTargets, Target);
      }
    }
    if (Expr->getNameInfo().getAsString() != "SIGNAL_GROUP_EXIT") {
      return true;
    }
    Event Item;
    Item.Node = Expr;
    Item.Key = "signal:SIGNAL_GROUP_EXIT";
    Item.Name = "SIGNAL_GROUP_EXIT";
    Item.Signal = true;
    PresumedLoc Location = SM.getPresumedLoc(SM.getExpansionLoc(Expr->getExprLoc()));
    if (Location.isValid()) {
      Item.Line = Location.getLine();
      Item.Column = Location.getColumn();
    }
    appendUnique(Record.SignalChecks, Item.Name);
    Events.push_back(std::move(Item));
    return true;
  }

  std::vector<Event> Events;

  void addParameter(ParmVarDecl *Decl) {
    if (!Decl || Decl->getName().empty()) {
      return;
    }
    appendUnique(Record.Parameters, Decl->getNameAsString());
    addStructVariable(Decl);
  }

private:
  void addStructVariable(ValueDecl *Decl) {
    if (Decl->getName().empty()) {
      return;
    }
    std::string Type = recordTypeName(Decl->getType());
    if (!Type.empty()) {
      Record.StructVariables.emplace(Decl->getNameAsString(), std::move(Type));
    }
  }

  ASTContext &Context;
  FunctionRecord &Record;
  const SourceManager &SM;
  const LangOptions &LangOpts;
  unsigned CallSiteOrdinal = 0;
};

const ReturnStmt *returnInBlock(const CFGBlock &Block) {
  for (const CFGElement &Element : Block) {
    if (auto CFGStatement = Element.getAs<CFGStmt>()) {
      if (const auto *Return = dyn_cast<ReturnStmt>(CFGStatement->getStmt())) {
        return Return;
      }
    }
  }
  return nullptr;
}

bool definitelyFailureReturn(const ReturnStmt *Return, ASTContext &Context) {
  if (!Return || !Return->getRetValue()) {
    return false;
  }
  Expr::EvalResult Result;
  const Expr *Value = Return->getRetValue()->IgnoreParenImpCasts();
  if (!Value->EvaluateAsInt(Result, Context)) {
    return false;
  }
  llvm::APSInt Integer = Result.Val.getInt();
  return Integer.isSigned() && Integer.isNegative();
}

const Expr *stripConditionWrappers(const Expr *Expression) {
  if (!Expression) {
    return nullptr;
  }
  Expression = Expression->IgnoreParenImpCasts();
  while (const auto *Call = dyn_cast<CallExpr>(Expression)) {
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || Call->getNumArgs() == 0) {
      break;
    }
    llvm::StringRef Name = Callee->getName();
    if (Name != "__builtin_expect" && Name != "__builtin_expect_with_probability") {
      break;
    }
    Expression = Call->getArg(0)->IgnoreParenImpCasts();
  }
  return Expression;
}

const ValueDecl *returnedValueDecl(const ReturnStmt *Return) {
  if (!Return || !Return->getRetValue()) {
    return nullptr;
  }
  const Expr *Value = Return->getRetValue()->IgnoreParenImpCasts();
  if (const auto *Reference = dyn_cast<DeclRefExpr>(Value)) {
    return Reference->getDecl();
  }
  return nullptr;
}

enum class ValueConstraint {
  Unknown,
  Zero,
  NonZero,
  Negative,
  NonNegative,
};

bool integerIsZero(const Expr *Expression, ASTContext &Context) {
  if (!Expression) {
    return false;
  }
  Expr::EvalResult Result;
  if (!Expression->IgnoreParenImpCasts()->EvaluateAsInt(Result, Context)) {
    return false;
  }
  return Result.Val.getInt() == 0;
}

bool referencesValue(const Expr *Expression, const ValueDecl *Value) {
  if (!Expression || !Value) {
    return false;
  }
  Expression = stripConditionWrappers(Expression);
  if (const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Expression)) {
    return Reference->getDecl() == Value;
  }
  return false;
}

ValueConstraint branchConstraint(const Expr *Condition, bool TrueBranch,
                                 const ValueDecl *Value,
                                 ASTContext &Context) {
  Condition = stripConditionWrappers(Condition);
  if (!Condition || !Value) {
    return ValueConstraint::Unknown;
  }
  if (const auto *Unary = dyn_cast<UnaryOperator>(Condition)) {
    if (Unary->getOpcode() == UO_LNot) {
      return branchConstraint(Unary->getSubExpr(), !TrueBranch, Value,
                              Context);
    }
  }
  if (referencesValue(Condition, Value)) {
    return TrueBranch ? ValueConstraint::NonZero : ValueConstraint::Zero;
  }
  const auto *Binary = dyn_cast<BinaryOperator>(Condition);
  if (!Binary || !Binary->isComparisonOp()) {
    return ValueConstraint::Unknown;
  }

  const Expr *Left = stripConditionWrappers(Binary->getLHS());
  const Expr *Right = stripConditionWrappers(Binary->getRHS());
  bool ValueOnLeft = referencesValue(Left, Value) && integerIsZero(Right, Context);
  bool ValueOnRight =
      referencesValue(Right, Value) && integerIsZero(Left, Context);
  if (!ValueOnLeft && !ValueOnRight) {
    return ValueConstraint::Unknown;
  }

  BinaryOperatorKind Opcode = Binary->getOpcode();
  if (ValueOnRight) {
    switch (Opcode) {
    case BO_LT:
      Opcode = BO_GT;
      break;
    case BO_LE:
      Opcode = BO_GE;
      break;
    case BO_GT:
      Opcode = BO_LT;
      break;
    case BO_GE:
      Opcode = BO_LE;
      break;
    default:
      break;
    }
  }
  switch (Opcode) {
  case BO_EQ:
    return TrueBranch ? ValueConstraint::Zero : ValueConstraint::NonZero;
  case BO_NE:
    return TrueBranch ? ValueConstraint::NonZero : ValueConstraint::Zero;
  case BO_LT:
    return TrueBranch ? ValueConstraint::Negative
                      : ValueConstraint::NonNegative;
  case BO_GE:
    return TrueBranch ? ValueConstraint::NonNegative
                      : ValueConstraint::Negative;
  default:
    return ValueConstraint::Unknown;
  }
}

const Expr *blockCondition(const CFGBlock &Block) {
  const Stmt *Terminator = Block.getTerminatorStmt();
  if (const auto *If = dyn_cast_or_null<IfStmt>(Terminator)) {
    return If->getCond();
  }
  if (const auto *While = dyn_cast_or_null<WhileStmt>(Terminator)) {
    return While->getCond();
  }
  if (const auto *For = dyn_cast_or_null<ForStmt>(Terminator)) {
    return For->getCond();
  }
  if (const auto *Conditional =
          dyn_cast_or_null<ConditionalOperator>(Terminator)) {
    return Conditional->getCond();
  }
  return nullptr;
}

std::string successorBranchKind(const CFGBlock &Block,
                                unsigned SuccessorIndex) {
  if (!blockCondition(Block)) {
    return "unconditional";
  }
  if (SuccessorIndex == 0) {
    return "true";
  }
  if (SuccessorIndex == 1) {
    return "false";
  }
  return "unknown";
}

const ReturnStmt *linearReturnFrom(const CFG &Graph,
                                   const CFGBlock *Start) {
  std::set<unsigned> Seen;
  const CFGBlock *Current = Start;
  while (Current && Seen.insert(Current->getBlockID()).second) {
    if (const ReturnStmt *Return = returnInBlock(*Current)) {
      return Return;
    }
    const CFGBlock *OnlySuccessor = nullptr;
    unsigned SuccessorCount = 0;
    for (CFGBlock::const_succ_iterator Iterator = Current->succ_begin();
         Iterator != Current->succ_end(); ++Iterator) {
      const CFGBlock *Successor = *Iterator;
      if (!Successor || Successor == &Graph.getExit()) {
        continue;
      }
      OnlySuccessor = Successor;
      ++SuccessorCount;
    }
    if (SuccessorCount != 1 || Current->getTerminatorStmt()) {
      return nullptr;
    }
    Current = OnlySuccessor;
  }
  return nullptr;
}

bool branchEdgeIsFailureOnly(const CFG &Graph, const CFGBlock &Source,
                             const CFGBlock &Successor, unsigned SuccessorIndex,
                             ASTContext &Context) {
  const Expr *Condition = blockCondition(Source);
  if (!Condition || SuccessorIndex > 1) {
    return false;
  }
  const ReturnStmt *Return = linearReturnFrom(Graph, &Successor);
  if (!Return) {
    return false;
  }
  if (definitelyFailureReturn(Return, Context)) {
    return true;
  }
  const ValueDecl *Returned = returnedValueDecl(Return);
  if (!Returned) {
    return false;
  }
  ValueConstraint Constraint =
      branchConstraint(Condition, SuccessorIndex == 0, Returned, Context);
  return Constraint == ValueConstraint::Negative;
}

std::set<std::string> intersectSets(const std::set<std::string> &Left,
                                    const std::set<std::string> &Right) {
  std::set<std::string> Result;
  std::set_intersection(Left.begin(), Left.end(), Right.begin(), Right.end(),
                        std::inserter(Result, Result.begin()));
  return Result;
}

std::string expressionSource(const Expr *Expression, ASTContext &Context) {
  if (!Expression) {
    return {};
  }
  std::string Result =
      sourceText(Context.getSourceManager(), Context.getLangOpts(),
                 Expression->getSourceRange());
  if (!Result.empty()) {
    return Result;
  }
  PrintingPolicy Policy(Context.getLangOpts());
  llvm::raw_string_ostream Stream(Result);
  Expression->printPretty(Stream, nullptr, Policy);
  Stream.flush();
  return Result;
}

std::string callSiteIDForExpression(const Expr *Expression,
                                    const std::vector<Event> &Events) {
  if (!Expression) {
    return {};
  }
  const Expr *Value = Expression->IgnoreParenImpCasts();
  for (unsigned Depth = 0; Depth < 8; ++Depth) {
    const auto *Assignment = dyn_cast<BinaryOperator>(Value);
    if (!Assignment || Assignment->getOpcode() != BO_Assign) {
      break;
    }
    Value = Assignment->getRHS()->IgnoreParenImpCasts();
  }
  const auto *Call = dyn_cast<CallExpr>(Value);
  if (!Call) {
    return {};
  }
  for (const Event &Item : Events) {
    if (Item.Node == Call) {
      return Item.CallSiteID;
    }
  }
  return {};
}

void appendValueWrite(BlockRecord &Block, const ValueDecl *Target,
                      const Expr *Value, llvm::StringRef Kind,
                      ASTContext &Context,
                      const std::vector<Event> &Events) {
  if (!Target || Target->getName().empty()) {
    return;
  }
  ValueWrite Write;
  Write.Target = Target->getNameAsString();
  Write.Kind = Kind.str();
  TypeMetadata TargetType = describeType(Target->getType(), Context);
  Write.TargetTypeClass = TargetType.Class;
  Write.TargetTypeSigned = TargetType.Signed;
  Write.TargetTypeBits = TargetType.Bits;
  if (Value) {
    Write.Expression = expressionSource(Value, Context);
    PrintingPolicy Policy(Context.getLangOpts());
    llvm::raw_string_ostream Stream(Write.ExpressionExpanded);
    Value->printPretty(Stream, nullptr, Policy);
    Stream.flush();
    if (Write.Expression.empty()) {
      Write.Expression = Write.ExpressionExpanded;
    }
    Write.CallSiteID = callSiteIDForExpression(Value, Events);
    Write.SourceDefinitelyNonnegative =
        expressionDefinitelyNonnegative(Value, Context);
    Write.SourceDefinitelyValidPointer =
        expressionDefinitelyValidPointer(Value);
    TypeMetadata SourceType =
        describeType(Value->IgnoreParenImpCasts()->getType(), Context);
    Write.SourceTypeClass = SourceType.Class;
    Write.SourceTypeSigned = SourceType.Signed;
    Write.SourceTypeBits = SourceType.Bits;
  }
  Block.ValueWrites.push_back(std::move(Write));
}

const ParmVarDecl *pointeeParameterTarget(const Expr *Expression) {
  if (!Expression) {
    return nullptr;
  }
  const Expr *Value = Expression->IgnoreParenImpCasts();
  const auto *Dereference = dyn_cast<UnaryOperator>(Value);
  if (!Dereference || Dereference->getOpcode() != UO_Deref) {
    return nullptr;
  }
  const DeclRefExpr *Reference =
      declRefTarget(Dereference->getSubExpr());
  return Reference
             ? dyn_cast<ParmVarDecl>(Reference->getDecl())
             : nullptr;
}

void appendPointeeWrite(BlockRecord &Block, const ParmVarDecl *Parameter,
                        const Expr *Target, const Expr *Value,
                        llvm::StringRef Kind, ASTContext &Context) {
  if (!Parameter || Parameter->getName().empty() || !Target) {
    return;
  }
  PointeeWrite Write;
  Write.Parameter = Parameter->getNameAsString();
  Write.Kind = Kind.str();
  TypeMetadata TargetType = describeType(Target->getType(), Context);
  Write.TargetTypeClass = TargetType.Class;
  Write.TargetTypeSigned = TargetType.Signed;
  Write.TargetTypeBits = TargetType.Bits;
  if (Value) {
    Write.Expression = expressionSource(Value, Context);
    Write.SourceDefinitelyNonnegative =
        expressionDefinitelyNonnegative(Value, Context);
    Write.SourceDefinitelyValidPointer =
        expressionDefinitelyValidPointer(Value);
    TypeMetadata SourceType =
        describeType(Value->IgnoreParenImpCasts()->getType(), Context);
    Write.SourceTypeClass = SourceType.Class;
    Write.SourceTypeSigned = SourceType.Signed;
    Write.SourceTypeBits = SourceType.Bits;
  }
  Block.PointeeWrites.push_back(std::move(Write));
}

void collectValueWrites(const Stmt *Statement, BlockRecord &Block,
                        ASTContext &Context,
                        const std::vector<Event> &Events) {
  if (!Statement) {
    return;
  }
  if (const auto *Declaration = dyn_cast<DeclStmt>(Statement)) {
    for (const Decl *Item : Declaration->decls()) {
      const auto *Variable = dyn_cast<VarDecl>(Item);
      if (!Variable || !Variable->hasInit()) {
        continue;
      }
      appendValueWrite(Block, Variable, Variable->getInit(), "initialize",
                       Context, Events);
    }
    return;
  }
  if (const auto *Binary = dyn_cast<BinaryOperator>(Statement)) {
    if (!Binary->isAssignmentOp()) {
      return;
    }
    const DeclRefExpr *Reference = declRefTarget(Binary->getLHS());
    const ParmVarDecl *Pointee =
        pointeeParameterTarget(Binary->getLHS());
    if (Pointee) {
      if (Binary->getOpcode() == BO_Assign) {
        appendPointeeWrite(Block, Pointee, Binary->getLHS(),
                           Binary->getRHS(), "assign", Context);
      } else {
        appendPointeeWrite(Block, Pointee, Binary->getLHS(), nullptr,
                           "invalidate", Context);
      }
      return;
    }
    if (!Reference) {
      return;
    }
    if (Binary->getOpcode() == BO_Assign) {
      appendValueWrite(Block, Reference->getDecl(), Binary->getRHS(),
                       "assign", Context, Events);
    } else {
      appendValueWrite(Block, Reference->getDecl(), nullptr, "invalidate",
                       Context, Events);
    }
    return;
  }
  if (const auto *Unary = dyn_cast<UnaryOperator>(Statement)) {
    if (!Unary->isIncrementDecrementOp()) {
      return;
    }
    if (const ParmVarDecl *Pointee =
            pointeeParameterTarget(Unary->getSubExpr())) {
      appendPointeeWrite(Block, Pointee, Unary->getSubExpr(), nullptr,
                         "invalidate", Context);
      return;
    }
    const DeclRefExpr *Reference = declRefTarget(Unary->getSubExpr());
    if (Reference) {
      appendValueWrite(Block, Reference->getDecl(), nullptr, "invalidate",
                       Context, Events);
    }
  }
}

void analyzeCFG(FunctionDecl *Function, ASTContext &Context,
                const std::vector<Event> &Events, FunctionRecord &Record) {
  CFG::BuildOptions BuildOptions;
  BuildOptions.AddInitializers = true;
  BuildOptions.AddImplicitDtors = false;
  BuildOptions.AddTemporaryDtors = false;
  std::unique_ptr<CFG> Graph =
      CFG::buildCFG(Function, Function->getBody(), &Context, BuildOptions);
  if (!Graph) {
    Record.CFGFailure = "clang_cfg_build_failed";
    return;
  }

  Record.CFGComplete = true;
  const unsigned BlockCount = Graph->getNumBlockIDs();
  const unsigned EntryID = Graph->getEntry().getBlockID();
  const unsigned ExitID = Graph->getExit().getBlockID();
  Record.CFGEntry = EntryID;
  Record.CFGExit = ExitID;
  std::vector<const CFGBlock *> ByID(BlockCount, nullptr);
  std::vector<std::vector<unsigned>> Predecessors(BlockCount);
  std::vector<std::vector<unsigned>> SuccessPredecessors(BlockCount);
  std::vector<std::set<std::string>> BlockEvents(BlockCount);
  std::unordered_map<const Stmt *, unsigned> EventBlocks;
  std::set<std::pair<unsigned, unsigned>> FailureEdges;

  for (const CFGBlock *Block : *Graph) {
    if (!Block) {
      continue;
    }
    ByID[Block->getBlockID()] = Block;
    for (const CFGElement &Element : *Block) {
      auto CFGStatement = Element.getAs<CFGStmt>();
      if (!CFGStatement) {
        continue;
      }
      const Stmt *Statement = CFGStatement->getStmt();
      for (const Event &Item : Events) {
        if (Item.Node == Statement) {
          EventBlocks[Item.Node] = Block->getBlockID();
        }
      }
    }
  }

  for (const Event &Item : Events) {
    if (EventBlocks.count(Item.Node)) {
      continue;
    }
    unsigned BestSize = 0;
    unsigned BestBlock = 0;
    bool FoundCandidate = false;
    bool Ambiguous = false;
    for (const CFGBlock *Block : *Graph) {
      if (!Block) {
        continue;
      }
      for (const CFGElement &Element : *Block) {
        auto CFGStatement = Element.getAs<CFGStmt>();
        if (!CFGStatement) {
          continue;
        }
        const Stmt *Statement = CFGStatement->getStmt();
        if (!containsStmt(Statement, Item.Node) &&
            !sourceRangeContains(Statement, Item.Node,
                                 Context.getSourceManager(),
                                 Context.getLangOpts())) {
          continue;
        }
        unsigned Size = stmtNodeCount(Statement);
        if (!FoundCandidate || Size < BestSize) {
          BestSize = Size;
          BestBlock = Block->getBlockID();
          FoundCandidate = true;
          Ambiguous = false;
        } else if (Size == BestSize && BestBlock != Block->getBlockID()) {
          Ambiguous = true;
        }
      }
    }
    if (FoundCandidate && !Ambiguous) {
      EventBlocks[Item.Node] = BestBlock;
    } else {
      appendUnique(Record.UnplacedEvents, diagnosticEventKey(Item));
      if (!Item.CallSiteID.empty()) {
        appendUnique(Record.UnplacedCallSiteIDs, Item.CallSiteID);
      }
    }
  }

  for (const Event &Item : Events) {
    auto Found = EventBlocks.find(Item.Node);
    if (Found != EventBlocks.end()) {
      BlockEvents[Found->second].insert(Item.Key);
    }
  }

  for (const CFGBlock *Block : *Graph) {
    if (!Block) {
      continue;
    }
    BlockRecord Item;
    Item.ID = Block->getBlockID();
    if (const Expr *Condition = blockCondition(*Block)) {
      Item.TerminatorCondition =
          sourceText(Context.getSourceManager(), Context.getLangOpts(),
                     Condition->getSourceRange());
      if (Item.TerminatorCondition.empty()) {
        PrintingPolicy Policy(Context.getLangOpts());
        llvm::raw_string_ostream Stream(Item.TerminatorCondition);
        Condition->printPretty(Stream, nullptr, Policy);
        Stream.flush();
      }
    }
    if (const ReturnStmt *Return = returnInBlock(*Block)) {
      if (const Expr *Value = Return->getRetValue()) {
        Item.ReturnExpression =
            sourceText(Context.getSourceManager(), Context.getLangOpts(),
                       Value->getSourceRange());
        PrintingPolicy Policy(Context.getLangOpts());
        llvm::raw_string_ostream Stream(Item.ReturnExpressionExpanded);
        Value->printPretty(Stream, nullptr, Policy);
        Stream.flush();
        if (Item.ReturnExpression.empty()) {
          Item.ReturnExpression = Item.ReturnExpressionExpanded;
        }
        Item.ReturnDefinitelyNonnegative =
            expressionDefinitelyNonnegative(Value, Context);
        Item.ReturnDefinitelyValidPointer =
            expressionDefinitelyValidPointer(Value);
      }
    }
    for (const CFGElement &Element : *Block) {
      auto CFGStatement = Element.getAs<CFGStmt>();
      if (!CFGStatement) {
        continue;
      }
      collectValueWrites(CFGStatement->getStmt(), Item, Context, Events);
    }
    unsigned SuccessorIndex = 0;
    for (CFGBlock::const_succ_iterator Iterator = Block->succ_begin();
         Iterator != Block->succ_end(); ++Iterator, ++SuccessorIndex) {
      const CFGBlock *Successor = *Iterator;
      if (!Successor) {
        continue;
      }
      Item.Successors.push_back(Successor->getBlockID());
      Item.SuccessorBranches.push_back(
          successorBranchKind(*Block, SuccessorIndex));
      Predecessors[Successor->getBlockID()].push_back(Block->getBlockID());
      if (branchEdgeIsFailureOnly(*Graph, *Block, *Successor, SuccessorIndex,
                                  Context)) {
        FailureEdges.emplace(Block->getBlockID(), Successor->getBlockID());
        Record.UsedKernelErrnoGuards = true;
      } else {
        Item.SuccessSuccessors.push_back(Successor->getBlockID());
        Item.SuccessSuccessorBranches.push_back(
            successorBranchKind(*Block, SuccessorIndex));
        SuccessPredecessors[Successor->getBlockID()].push_back(
            Block->getBlockID());
      }
    }
    for (const Event &EventItem : Events) {
      auto Found = EventBlocks.find(EventItem.Node);
      if (Found == EventBlocks.end() || Found->second != Item.ID) {
        continue;
      }
      if (EventItem.Direct) {
        appendUnique(Item.Calls, EventItem.Name);
      } else if (!EventItem.Expression.empty()) {
        appendUnique(Item.IndirectCalls, EventItem.Expression);
      }
      if (EventItem.LSM) {
        appendUnique(Item.LSMHooks, EventItem.Name);
      }
      if (EventItem.Signal) {
        appendUnique(Item.SignalChecks, EventItem.Name);
      }
      if (!EventItem.CallSiteID.empty()) {
        appendUnique(Item.CallSiteIDs, EventItem.CallSiteID);
      }
    }
    Record.Blocks.push_back(std::move(Item));
  }

  std::vector<bool> AllReachable(BlockCount, false);
  std::deque<unsigned> AllQueue;
  AllReachable[EntryID] = true;
  AllQueue.push_back(EntryID);
  while (!AllQueue.empty()) {
    unsigned Current = AllQueue.front();
    AllQueue.pop_front();
    const CFGBlock *Block = ByID[Current];
    if (!Block) {
      continue;
    }
    for (CFGBlock::const_succ_iterator Iterator = Block->succ_begin();
         Iterator != Block->succ_end(); ++Iterator) {
      const CFGBlock *Successor = *Iterator;
      if (!Successor || AllReachable[Successor->getBlockID()]) {
        continue;
      }
      AllReachable[Successor->getBlockID()] = true;
      AllQueue.push_back(Successor->getBlockID());
    }
  }
  for (const Event &Item : Events) {
    auto Found = EventBlocks.find(Item.Node);
    if (Found == EventBlocks.end() || !AllReachable[Found->second]) {
      continue;
    }
    if (Item.Direct) {
      appendUnique(Record.ReachableCalls, Item.Name);
      if (llvm::StringRef(Item.Name).startswith("security_")) {
        appendUnique(Record.ReachableLSMHooks, Item.Name);
      }
    } else if (!Item.Expression.empty()) {
      appendUnique(Record.ReachableIndirectCalls, Item.Expression);
    }
    if (Item.Signal) {
      appendUnique(Record.ReachableSignalChecks, Item.Name);
    }
    if (!Item.CallSiteID.empty()) {
      appendUnique(Record.ReachableCallSiteIDs, Item.CallSiteID);
    }
  }

  std::vector<bool> Reachable(BlockCount, false);
  std::deque<unsigned> Queue;
  Reachable[EntryID] = true;
  Queue.push_back(EntryID);
  while (!Queue.empty()) {
    unsigned Current = Queue.front();
    Queue.pop_front();
    const CFGBlock *Block = ByID[Current];
    if (!Block) {
      continue;
    }
    for (CFGBlock::const_succ_iterator Iterator = Block->succ_begin();
         Iterator != Block->succ_end(); ++Iterator) {
      const CFGBlock *Successor = *Iterator;
      if (!Successor ||
          FailureEdges.count({Current, Successor->getBlockID()}) ||
          Reachable[Successor->getBlockID()]) {
        continue;
      }
      Reachable[Successor->getBlockID()] = true;
      Queue.push_back(Successor->getBlockID());
    }
  }

  std::set<std::string> Universe;
  for (const Event &Item : Events) {
    Universe.insert(Item.Key);
  }
  std::vector<std::set<std::string>> In(BlockCount, Universe);
  std::vector<std::set<std::string>> Out(BlockCount, Universe);
  In[EntryID].clear();
  Out[EntryID] = BlockEvents[EntryID];

  bool Changed = true;
  unsigned Iterations = 0;
  while (Changed && Iterations++ < BlockCount * 4 + 16) {
    Changed = false;
    for (unsigned ID = 0; ID < BlockCount; ++ID) {
      if (!Reachable[ID] || ID == EntryID || !ByID[ID]) {
        continue;
      }
      bool First = true;
      std::set<std::string> NewIn;
      for (unsigned Predecessor : SuccessPredecessors[ID]) {
        if (!Reachable[Predecessor]) {
          continue;
        }
        if (First) {
          NewIn = Out[Predecessor];
          First = false;
        } else {
          NewIn = intersectSets(NewIn, Out[Predecessor]);
        }
      }
      if (First) {
        continue;
      }
      std::set<std::string> NewOut = NewIn;
      NewOut.insert(BlockEvents[ID].begin(), BlockEvents[ID].end());
      if (NewIn != In[ID] || NewOut != Out[ID]) {
        In[ID] = std::move(NewIn);
        Out[ID] = std::move(NewOut);
        Changed = true;
      }
    }
  }

  bool FirstSuccess = true;
  std::set<std::string> MustEvents;
  for (unsigned Predecessor : SuccessPredecessors[ExitID]) {
    if (!Reachable[Predecessor] || !ByID[Predecessor]) {
      continue;
    }
    const ReturnStmt *Return = returnInBlock(*ByID[Predecessor]);
    bool FailureOnly = definitelyFailureReturn(Return, Context);
    for (BlockRecord &Block : Record.Blocks) {
      if (Block.ID != Predecessor) {
        continue;
      }
      Block.FailureOnlyExit = FailureOnly;
      Block.PotentialSuccessExit = !FailureOnly;
      break;
    }
    if (FailureOnly) {
      continue;
    }
    Record.HasPotentialSuccessExit = true;
    if (FirstSuccess) {
      MustEvents = Out[Predecessor];
      FirstSuccess = false;
    } else {
      MustEvents = intersectSets(MustEvents, Out[Predecessor]);
    }
  }

  if (!Record.HasPotentialSuccessExit) {
    return;
  }
  for (const Event &Item : Events) {
    if (!MustEvents.count(Item.Key)) {
      continue;
    }
    if (Item.Direct) {
      appendUnique(Record.MustSuccessCalls, Item.Name);
      if (llvm::StringRef(Item.Name).startswith("security_")) {
        appendUnique(Record.MustSuccessLSMHooks, Item.Name);
      }
    } else if (!Item.Expression.empty()) {
      appendUnique(Record.MustSuccessIndirectCalls, Item.Expression);
    }
    if (Item.Signal) {
      appendUnique(Record.MustSuccessSignalChecks, Item.Name);
    }
    if (!Item.CallSiteID.empty()) {
      appendUnique(Record.MustSuccessCallSiteIDs, Item.CallSiteID);
    }
  }
}

llvm::json::Array stringsJSON(const std::vector<std::string> &Values) {
  llvm::json::Array Result;
  for (const std::string &Value : Values) {
    Result.push_back(Value);
  }
  return Result;
}

llvm::json::Object functionJSON(const FunctionRecord &Record) {
  llvm::json::Object StructVariables;
  for (const auto &Entry : Record.StructVariables) {
    StructVariables[Entry.first] = Entry.second;
  }
  llvm::json::Array Blocks;
  for (const BlockRecord &Block : Record.Blocks) {
    llvm::json::Array Successors;
    for (unsigned Successor : Block.Successors) {
      Successors.push_back(static_cast<int64_t>(Successor));
    }
    llvm::json::Array SuccessorBranches;
    for (const std::string &Branch : Block.SuccessorBranches) {
      SuccessorBranches.push_back(Branch);
    }
    llvm::json::Array SuccessSuccessors;
    for (unsigned Successor : Block.SuccessSuccessors) {
      SuccessSuccessors.push_back(static_cast<int64_t>(Successor));
    }
    llvm::json::Array SuccessSuccessorBranches;
    for (const std::string &Branch : Block.SuccessSuccessorBranches) {
      SuccessSuccessorBranches.push_back(Branch);
    }
    llvm::json::Array ValueWrites;
    for (const ValueWrite &Write : Block.ValueWrites) {
      ValueWrites.push_back(llvm::json::Object{
          {"target", Write.Target},
          {"expression", Write.Expression},
          {"expression_expanded", Write.ExpressionExpanded},
          {"kind", Write.Kind},
          {"callsite_id", Write.CallSiteID},
          {"source_definitely_nonnegative",
           Write.SourceDefinitelyNonnegative},
          {"source_definitely_valid_pointer",
           Write.SourceDefinitelyValidPointer},
          {"source_type_class", Write.SourceTypeClass},
          {"source_type_signed", Write.SourceTypeSigned},
          {"source_type_bits", static_cast<int64_t>(Write.SourceTypeBits)},
          {"target_type_class", Write.TargetTypeClass},
          {"target_type_signed", Write.TargetTypeSigned},
          {"target_type_bits", static_cast<int64_t>(Write.TargetTypeBits)},
      });
    }
    llvm::json::Array PointeeWrites;
    for (const PointeeWrite &Write : Block.PointeeWrites) {
      PointeeWrites.push_back(llvm::json::Object{
          {"parameter", Write.Parameter},
          {"expression", Write.Expression},
          {"kind", Write.Kind},
          {"source_definitely_nonnegative",
           Write.SourceDefinitelyNonnegative},
          {"source_definitely_valid_pointer",
           Write.SourceDefinitelyValidPointer},
          {"source_type_class", Write.SourceTypeClass},
          {"source_type_signed", Write.SourceTypeSigned},
          {"source_type_bits", static_cast<int64_t>(Write.SourceTypeBits)},
          {"target_type_class", Write.TargetTypeClass},
          {"target_type_signed", Write.TargetTypeSigned},
          {"target_type_bits", static_cast<int64_t>(Write.TargetTypeBits)},
      });
    }
    Blocks.push_back(llvm::json::Object{
        {"id", static_cast<int64_t>(Block.ID)},
        {"successors", std::move(Successors)},
        {"successor_branches", std::move(SuccessorBranches)},
        {"success_successors", std::move(SuccessSuccessors)},
        {"success_successor_branches",
         std::move(SuccessSuccessorBranches)},
        {"terminator_condition", Block.TerminatorCondition},
        {"return_expression", Block.ReturnExpression},
        {"return_expression_expanded", Block.ReturnExpressionExpanded},
        {"return_definitely_nonnegative",
         Block.ReturnDefinitelyNonnegative},
        {"return_definitely_valid_pointer",
         Block.ReturnDefinitelyValidPointer},
        {"calls", stringsJSON(Block.Calls)},
        {"indirect_calls", stringsJSON(Block.IndirectCalls)},
        {"lsm_hooks", stringsJSON(Block.LSMHooks)},
        {"signal_checks", stringsJSON(Block.SignalChecks)},
        {"callsite_ids", stringsJSON(Block.CallSiteIDs)},
        {"value_writes", std::move(ValueWrites)},
        {"pointee_writes", std::move(PointeeWrites)},
        {"potential_success_exit", Block.PotentialSuccessExit},
        {"failure_only_exit", Block.FailureOnlyExit},
    });
  }
  llvm::json::Array CallTargets;
  for (const CallTarget &Target : Record.CallTargets) {
    CallTargets.push_back(llvm::json::Object{
        {"name", Target.Name},
        {"file", Target.File},
        {"return_type", Target.ReturnType},
        {"return_type_canonical", Target.ReturnTypeCanonical},
        {"return_type_class", Target.ReturnTypeClass},
        {"return_type_signed", Target.ReturnTypeSigned},
        {"return_type_bits", static_cast<int64_t>(Target.ReturnTypeBits)},
        {"static", Target.Static},
        {"inline", Target.Inline},
        {"semantic_hash", Target.SemanticHash},
        {"line", static_cast<int64_t>(Target.Line)},
    });
  }
  llvm::json::Array IndirectTargets;
  for (const IndirectTarget &Target : Record.IndirectTargets) {
    IndirectTargets.push_back(llvm::json::Object{
        {"expression", Target.Expression},
        {"struct_type", Target.StructType},
        {"field", Target.Field},
        {"return_type", Target.ReturnType},
        {"return_type_canonical", Target.ReturnTypeCanonical},
        {"return_type_class", Target.ReturnTypeClass},
        {"return_type_signed", Target.ReturnTypeSigned},
        {"return_type_bits", static_cast<int64_t>(Target.ReturnTypeBits)},
    });
  }
  llvm::json::Array CallSites;
  for (const CallSite &Site : Record.CallSites) {
    llvm::json::Array CallbackArguments;
    for (const CallbackArgument &Argument : Site.CallbackArguments) {
      llvm::json::Array Targets;
      for (const CallTarget &Target : Argument.Targets) {
        Targets.push_back(llvm::json::Object{
            {"name", Target.Name},
            {"file", Target.File},
            {"return_type", Target.ReturnType},
            {"return_type_canonical", Target.ReturnTypeCanonical},
            {"return_type_class", Target.ReturnTypeClass},
            {"return_type_signed", Target.ReturnTypeSigned},
            {"return_type_bits",
             static_cast<int64_t>(Target.ReturnTypeBits)},
            {"static", Target.Static},
            {"inline", Target.Inline},
            {"semantic_hash", Target.SemanticHash},
            {"line", static_cast<int64_t>(Target.Line)},
        });
      }
      CallbackArguments.push_back(llvm::json::Object{
          {"index", static_cast<int64_t>(Argument.Index)},
          {"complete", Argument.Complete},
          {"may_be_null", Argument.MayBeNull},
          {"targets", std::move(Targets)},
      });
    }
    CallSites.push_back(llvm::json::Object{
        {"id", Site.ID},
        {"direct", Site.Direct},
        {"reachable", Site.Reachable},
        {"block_id", static_cast<int64_t>(Site.BlockID)},
        {"has_block", Site.HasBlock},
        {"name", Site.Name},
        {"expression", Site.Expression},
        {"result_use", Site.ResultUse},
        {"result_variable", Site.ResultVariable},
        {"return_type", Site.ReturnType},
        {"return_type_canonical", Site.ReturnTypeCanonical},
        {"return_type_class", Site.ReturnTypeClass},
        {"return_type_signed", Site.ReturnTypeSigned},
        {"return_type_bits", static_cast<int64_t>(Site.ReturnTypeBits)},
        {"arguments", stringsJSON(Site.Arguments)},
        {"argument_constants", stringsJSON(Site.ArgumentConstants)},
        {"callback_arguments", std::move(CallbackArguments)},
        {"line", static_cast<int64_t>(Site.Line)},
        {"column", static_cast<int64_t>(Site.Column)},
        {"spelling_line", static_cast<int64_t>(Site.SpellingLine)},
        {"spelling_column", static_cast<int64_t>(Site.SpellingColumn)},
        {"macro_expansion", Site.MacroExpansion},
    });
  }
  return llvm::json::Object{
      {"kind", "function"},
      {"name", Record.Name},
      {"file", Record.File},
      {"translation_unit", Record.TranslationUnit},
      {"line", static_cast<int64_t>(Record.Line)},
      {"column", static_cast<int64_t>(Record.Column)},
      {"return_type", Record.ReturnType},
      {"return_type_canonical", Record.ReturnTypeCanonical},
      {"return_type_class", Record.ReturnTypeClass},
      {"return_type_signed", Record.ReturnTypeSigned},
      {"return_type_bits", static_cast<int64_t>(Record.ReturnTypeBits)},
      {"static", Record.Static},
      {"inline", Record.Inline},
      {"semantic_hash", Record.SemanticHash},
      {"parameters", stringsJSON(Record.Parameters)},
      {"struct_variables", std::move(StructVariables)},
      {"body", Record.Body},
      {"direct_calls", stringsJSON(Record.DirectCalls)},
      {"indirect_calls", stringsJSON(Record.IndirectCalls)},
      {"lsm_hooks", stringsJSON(Record.LSMHooks)},
      {"signal_checks", stringsJSON(Record.SignalChecks)},
      {"direct_call_targets", std::move(CallTargets)},
      {"indirect_call_targets", std::move(IndirectTargets)},
      {"call_sites", std::move(CallSites)},
      {"reachable_calls", stringsJSON(Record.ReachableCalls)},
      {"reachable_indirect_calls",
       stringsJSON(Record.ReachableIndirectCalls)},
      {"reachable_lsm_hooks", stringsJSON(Record.ReachableLSMHooks)},
      {"reachable_signal_checks",
       stringsJSON(Record.ReachableSignalChecks)},
      {"must_success_calls", stringsJSON(Record.MustSuccessCalls)},
      {"must_success_indirect_calls",
       stringsJSON(Record.MustSuccessIndirectCalls)},
      {"must_success_lsm_hooks", stringsJSON(Record.MustSuccessLSMHooks)},
      {"must_success_signal_checks",
       stringsJSON(Record.MustSuccessSignalChecks)},
      {"reachable_callsite_ids", stringsJSON(Record.ReachableCallSiteIDs)},
      {"must_success_callsite_ids",
       stringsJSON(Record.MustSuccessCallSiteIDs)},
      {"unplaced_callsite_ids", stringsJSON(Record.UnplacedCallSiteIDs)},
      {"unplaced_events", stringsJSON(Record.UnplacedEvents)},
      {"escaped_variables", stringsJSON(Record.EscapedVariables)},
      {"cfg_complete", Record.CFGComplete},
      {"cfg_entry", static_cast<int64_t>(Record.CFGEntry)},
      {"cfg_exit", static_cast<int64_t>(Record.CFGExit)},
      {"cfg_has_potential_success_exit", Record.HasPotentialSuccessExit},
      {"cfg_used_kernel_errno_guards", Record.UsedKernelErrnoGuards},
      {"cfg_failure", Record.CFGFailure},
      {"cfg_blocks", std::move(Blocks)},
  };
}

const Expr *stripInitializerExpression(const Expr *Expression) {
  while (Expression) {
    Expression = Expression->IgnoreParenImpCasts();
    if (const auto *Cast = dyn_cast<CastExpr>(Expression)) {
      Expression = Cast->getSubExpr();
      continue;
    }
    if (const auto *Cleanup = dyn_cast<ExprWithCleanups>(Expression)) {
      Expression = Cleanup->getSubExpr();
      continue;
    }
    if (const auto *Constant = dyn_cast<ConstantExpr>(Expression)) {
      Expression = Constant->getSubExpr();
      continue;
    }
    break;
  }
  return Expression;
}

const FunctionDecl *initializerFunction(const Expr *Expression) {
  Expression = stripInitializerExpression(Expression);
  if (const auto *Address = dyn_cast_or_null<UnaryOperator>(Expression)) {
    if (Address->getOpcode() == UO_AddrOf) {
      Expression = stripInitializerExpression(Address->getSubExpr());
    }
  }
  const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Expression);
  if (!Reference) {
    return nullptr;
  }
  const auto *Function = dyn_cast<FunctionDecl>(Reference->getDecl());
  if (!Function) {
    return nullptr;
  }
  if (const FunctionDecl *Definition = Function->getDefinition()) {
    Function = Definition;
  }
  return Function;
}

bool nullFunctionPointerInitializer(const Expr *Expression,
                                    ASTContext &Context) {
  if (!Expression || isa<ImplicitValueInitExpr>(Expression) ||
      isa<CXXNullPtrLiteralExpr>(Expression) ||
      isa<GNUNullExpr>(Expression)) {
    return true;
  }
  Expression = stripInitializerExpression(Expression);
  return Expression &&
         Expression->isNullPointerConstant(
             Context, Expr::NPC_ValueDependentIsNotNull);
}

bool collectCallbackFunctionsImpl(
    const Expr *Expression, ASTContext &Context,
    std::vector<const FunctionDecl *> &Functions, bool &MayBeNull,
    std::set<const VarDecl *> &ActiveVariables) {
  if (!Expression) {
    return false;
  }
  if (nullFunctionPointerInitializer(Expression, Context)) {
    MayBeNull = true;
    return true;
  }
  Expression = stripInitializerExpression(Expression);
  if (!Expression) {
    return false;
  }
  if (const FunctionDecl *Function = initializerFunction(Expression)) {
    appendUnique(Functions, Function);
    return true;
  }
  if (const auto *Conditional = dyn_cast<ConditionalOperator>(Expression)) {
    return collectCallbackFunctionsImpl(
               Conditional->getTrueExpr(), Context, Functions, MayBeNull,
               ActiveVariables) &&
           collectCallbackFunctionsImpl(
               Conditional->getFalseExpr(), Context, Functions, MayBeNull,
               ActiveVariables);
  }
  if (const auto *Choose = dyn_cast<ChooseExpr>(Expression)) {
    if (Choose->isConditionDependent()) {
      return false;
    }
    return collectCallbackFunctionsImpl(
        Choose->getChosenSubExpr(), Context, Functions, MayBeNull,
        ActiveVariables);
  }
  if (const auto *Generic = dyn_cast<GenericSelectionExpr>(Expression)) {
    if (Generic->isResultDependent()) {
      return false;
    }
    return collectCallbackFunctionsImpl(
        Generic->getResultExpr(), Context, Functions, MayBeNull,
        ActiveVariables);
  }
  const auto *Reference = dyn_cast<DeclRefExpr>(Expression);
  const auto *Variable =
      Reference ? dyn_cast<VarDecl>(Reference->getDecl()) : nullptr;
  if (!Variable || !Variable->hasInit() ||
      !Variable->getType().isConstQualified() ||
      !ActiveVariables.insert(Variable).second) {
    return false;
  }
  bool Complete = collectCallbackFunctionsImpl(
      Variable->getInit(), Context, Functions, MayBeNull, ActiveVariables);
  ActiveVariables.erase(Variable);
  return Complete;
}

bool collectCallbackFunctions(const Expr *Expression, ASTContext &Context,
                              std::vector<const FunctionDecl *> &Functions,
                              bool &MayBeNull) {
  std::set<const VarDecl *> ActiveVariables;
  return collectCallbackFunctionsImpl(Expression, Context, Functions,
                                      MayBeNull, ActiveVariables);
}

llvm::json::Object operationTableJSON(
    const OperationTableRecord &Record) {
  llvm::json::Array Targets;
  for (const OperationFieldTarget &Target : Record.FieldTargets) {
    Targets.push_back(llvm::json::Object{
        {"field", Target.Field},
        {"function", Target.Function},
        {"file", Target.File},
    });
  }
  return llvm::json::Object{
      {"kind", "operation_table"},
      {"struct_type", Record.StructType},
      {"table", Record.Table},
      {"file", Record.File},
      {"const", Record.Const},
      {"complete", Record.Complete},
      {"field_targets", std::move(Targets)},
      {"null_fields", stringsJSON(Record.NullFields)},
      {"unknown_fields", stringsJSON(Record.UnknownFields)},
  };
}

class FunctionVisitor : public RecursiveASTVisitor<FunctionVisitor> {
public:
  FunctionVisitor(ASTContext &Context, llvm::StringRef KernelRoot,
                  llvm::StringRef TranslationUnit, std::set<std::string> &Seen,
                  llvm::raw_ostream &Output)
      : Context(Context), SM(Context.getSourceManager()),
        KernelRoot(KernelRoot.str()),
        TranslationUnit(canonicalPath(TranslationUnit)), Seen(Seen),
        Output(Output) {}

  bool VisitVarDecl(VarDecl *Variable) {
    if (!Variable || Variable->isImplicit() || !Variable->hasGlobalStorage() ||
        !Variable->hasInit() || Variable->getName().empty() ||
        Variable->getType()->isArrayType()) {
      return true;
    }
    const RecordType *Type =
        Variable->getType().getCanonicalType()->getAs<RecordType>();
    if (!Type) {
      return true;
    }
    const RecordDecl *Record = Type->getDecl()->getDefinition();
    if (!Record || Record->isUnion() || Record->getName().empty()) {
      return true;
    }
    const Expr *Initializer =
        stripInitializerExpression(Variable->getInit());
    const auto *List = dyn_cast_or_null<InitListExpr>(Initializer);
    if (!List) {
      return true;
    }
    if (const InitListExpr *Semantic = List->getSemanticForm()) {
      List = Semantic;
    }
    std::string File = locationFile(SM, Variable->getLocation());
    if (!pathWithin(KernelRoot, File)) {
      return true;
    }
    std::string Key = "operation-table\n" + File + "\n" +
                      Variable->getNameAsString();
    if (!Seen.insert(Key).second) {
      return true;
    }

    OperationTableRecord Result;
    Result.StructType = Record->getNameAsString();
    Result.Table = Variable->getNameAsString();
    Result.File = std::move(File);
    Result.Const = Variable->getType().isConstQualified();
    Result.Complete = true;
    unsigned FieldIndex = 0;
    bool SawFunctionPointer = false;
    for (const FieldDecl *Field : Record->fields()) {
      const Expr *FieldInitializer =
          FieldIndex < List->getNumInits()
              ? List->getInit(FieldIndex)
              : nullptr;
      ++FieldIndex;
      if (!Field->getType()->isFunctionPointerType()) {
        continue;
      }
      SawFunctionPointer = true;
      std::string FieldName = Field->getNameAsString();
      if (FieldName.empty()) {
        Result.Complete = false;
        continue;
      }
      if (nullFunctionPointerInitializer(FieldInitializer, Context)) {
        appendUnique(Result.NullFields, FieldName);
        continue;
      }
      const FunctionDecl *Function =
          initializerFunction(FieldInitializer);
      if (!Function || Function->getName().empty()) {
        appendUnique(Result.UnknownFields, FieldName);
        Result.Complete = false;
        continue;
      }
      Result.FieldTargets.push_back(OperationFieldTarget{
          FieldName,
          Function->getNameAsString(),
          locationFile(SM, Function->getLocation()),
      });
    }
    if (SawFunctionPointer) {
      Output << llvm::formatv(
          "{0}\n", llvm::json::Value(operationTableJSON(Result)));
    }
    return true;
  }

  bool VisitFunctionDecl(FunctionDecl *Function) {
    if (!Function->doesThisDeclarationHaveABody() || !Function->getBody() ||
        Function->isImplicit()) {
      return true;
    }
    std::string File = locationFile(SM, Function->getLocation());
    if (!pathWithin(KernelRoot, File)) {
      return true;
    }
    SourceLocation Expansion = SM.getExpansionLoc(Function->getLocation());
    PresumedLoc Presumed = SM.getPresumedLoc(Expansion);
    if (Presumed.isInvalid()) {
      return true;
    }
    std::string Name = Function->getNameAsString();
    if (Name.empty()) {
      return true;
    }
    std::string Key =
        File + "\n" + Name + "\n" + std::to_string(Presumed.getLine());
    ODRHash SemanticHash;
    SemanticHash.AddFunctionDecl(Function);
    std::string SemanticHashValue =
        std::to_string(SemanticHash.CalculateHash());
    Key += "\n" + SemanticHashValue;
    if (!Seen.insert(Key).second) {
      return true;
    }

    FunctionRecord Record;
    Record.Name = std::move(Name);
    Record.File = std::move(File);
    Record.TranslationUnit = TranslationUnit;
    Record.Line = Presumed.getLine();
    Record.Column = Presumed.getColumn();
    Record.Static = Function->getStorageClass() == SC_Static ||
                    Function->getFormalLinkage() == InternalLinkage;
    Record.Inline = Function->isInlined();
    if (Record.Static || Record.Inline) {
      Record.SemanticHash = std::move(SemanticHashValue);
    }
    TypeMetadata FunctionType =
        describeType(Function->getReturnType(), Context);
    Record.ReturnType = FunctionType.Spelling;
    Record.ReturnTypeCanonical = FunctionType.Canonical;
    Record.ReturnTypeClass = FunctionType.Class;
    Record.ReturnTypeSigned = FunctionType.Signed;
    Record.ReturnTypeBits = FunctionType.Bits;
    Record.Body =
        sourceText(SM, Context.getLangOpts(), Function->getBody()->getSourceRange());

    BodyVisitor Visitor(Context, Record);
    for (ParmVarDecl *Parameter : Function->parameters()) {
      Visitor.addParameter(Parameter);
    }
    Visitor.TraverseStmt(Function->getBody());
    analyzeCFG(Function, Context, Visitor.Events, Record);
    for (CallSite &Site : Record.CallSites) {
      Site.Reachable =
          std::find(Record.ReachableCallSiteIDs.begin(),
                    Record.ReachableCallSiteIDs.end(),
                    Site.ID) != Record.ReachableCallSiteIDs.end();
      for (const BlockRecord &Block : Record.Blocks) {
        if (std::find(Block.CallSiteIDs.begin(), Block.CallSiteIDs.end(),
                      Site.ID) == Block.CallSiteIDs.end()) {
          continue;
        }
        Site.BlockID = Block.ID;
        Site.HasBlock = true;
        break;
      }
    }
    Output << llvm::formatv("{0}\n", llvm::json::Value(functionJSON(Record)));
    return true;
  }

private:
  ASTContext &Context;
  const SourceManager &SM;
  std::string KernelRoot;
  std::string TranslationUnit;
  std::set<std::string> &Seen;
  llvm::raw_ostream &Output;
};

class ExtractConsumer : public ASTConsumer {
public:
  ExtractConsumer(ASTContext &Context, llvm::StringRef KernelRoot,
                  llvm::StringRef TranslationUnit, std::set<std::string> &Seen,
                  llvm::raw_ostream &Output)
      : Visitor(Context, KernelRoot, TranslationUnit, Seen, Output) {}

  void HandleTranslationUnit(ASTContext &Context) override {
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
  }

private:
  FunctionVisitor Visitor;
};

class ExtractAction : public ASTFrontendAction {
public:
  ExtractAction(llvm::StringRef KernelRoot, std::set<std::string> &Seen,
                llvm::raw_ostream &Output, unsigned &Completed)
      : KernelRoot(KernelRoot.str()), Seen(Seen), Output(Output),
        Completed(Completed) {}

  std::unique_ptr<ASTConsumer>
  CreateASTConsumer(CompilerInstance &Compiler,
                    llvm::StringRef InputFile) override {
    return std::make_unique<ExtractConsumer>(
        Compiler.getASTContext(), KernelRoot, InputFile, Seen, Output);
  }

  void EndSourceFileAction() override {
    ++Completed;
    if (Completed == 1 || Completed % 100 == 0) {
      llvm::errs() << "clang extraction: " << Completed << "\n";
    }
  }

private:
  std::string KernelRoot;
  std::set<std::string> &Seen;
  llvm::raw_ostream &Output;
  unsigned &Completed;
};

class ExtractFactory : public FrontendActionFactory {
public:
  ExtractFactory(llvm::StringRef KernelRoot, llvm::raw_ostream &Output)
      : KernelRoot(KernelRoot.str()), Output(Output) {}

  std::unique_ptr<FrontendAction> create() override {
    return std::make_unique<ExtractAction>(KernelRoot, Seen, Output, Completed);
  }

private:
  std::string KernelRoot;
  llvm::raw_ostream &Output;
  std::set<std::string> Seen;
  unsigned Completed = 0;
};

bool parseOptions(int argc, const char **argv, Options &Result) {
  for (int Index = 1; Index < argc; ++Index) {
    llvm::StringRef Argument(argv[Index]);
    auto ReadValue = [&](std::string &Destination) -> bool {
      if (Index + 1 >= argc) {
        llvm::errs() << "missing value for " << Argument << "\n";
        return false;
      }
      Destination = argv[++Index];
      return true;
    };
    if (Argument == "--compile-db") {
      if (!ReadValue(Result.CompileDB)) {
        return false;
      }
    } else if (Argument == "--files-from") {
      if (!ReadValue(Result.FilesFrom)) {
        return false;
      }
    } else if (Argument == "--kernel-root") {
      if (!ReadValue(Result.KernelRoot)) {
        return false;
      }
    } else if (Argument == "--output") {
      if (!ReadValue(Result.Output)) {
        return false;
      }
    } else if (Argument == "--help" || Argument == "-h") {
      llvm::outs()
          << "usage: clang_kernel_extractor --compile-db FILE "
             "--files-from FILE --kernel-root DIR --output FILE\n";
      return false;
    } else {
      llvm::errs() << "unknown argument: " << Argument << "\n";
      return false;
    }
  }
  if (Result.CompileDB.empty() || Result.FilesFrom.empty() ||
      Result.KernelRoot.empty() || Result.Output.empty()) {
    llvm::errs() << "all of --compile-db, --files-from, --kernel-root, and "
                    "--output are required\n";
    return false;
  }
  Result.CompileDB = canonicalPath(Result.CompileDB);
  Result.FilesFrom = canonicalPath(Result.FilesFrom);
  Result.KernelRoot = canonicalPath(Result.KernelRoot);
  return true;
}

std::vector<std::string> readFiles(llvm::StringRef Path) {
  std::ifstream Input(Path.str());
  std::vector<std::string> Result;
  std::string Line;
  while (std::getline(Input, Line)) {
    if (Line.empty()) {
      continue;
    }
    appendUnique(Result, canonicalPath(Line));
  }
  return Result;
}

} // namespace

int main(int argc, const char **argv) {
  Options ToolOptions;
  if (!parseOptions(argc, argv, ToolOptions)) {
    return 2;
  }

  std::string Error;
  std::unique_ptr<JSONCompilationDatabase> Database =
      JSONCompilationDatabase::loadFromFile(
          ToolOptions.CompileDB, Error, JSONCommandLineSyntax::AutoDetect);
  if (!Database) {
    llvm::errs() << "load compilation database: " << Error << "\n";
    return 1;
  }
  std::vector<std::string> Files = readFiles(ToolOptions.FilesFrom);
  if (Files.empty()) {
    llvm::errs() << "no translation units listed in " << ToolOptions.FilesFrom
                 << "\n";
    return 1;
  }

  std::error_code OutputError;
  llvm::raw_fd_ostream Output(ToolOptions.Output, OutputError,
                              llvm::sys::fs::OF_Text);
  if (OutputError) {
    llvm::errs() << "open output: " << OutputError.message() << "\n";
    return 1;
  }

  ClangTool Tool(*Database, Files);
  ExtractFactory Factory(ToolOptions.KernelRoot, Output);
  int Status = Tool.run(&Factory);
  Output.flush();
  return Status;
}
