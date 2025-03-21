// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include "vanir/language_parsers/cpp/parser_core.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "FunctionLexer.h"
#include "ModuleLexer.h"

namespace vanir {
namespace cpp_parser {

namespace {

using ::antlr4::tree::ParseTreeWalker;
using ::fuzzyc_cc_function::FunctionLexer;
using ::fuzzyc_cc_function::FunctionParser;
using ::fuzzyc_cc_module::ModuleLexer;
using ::fuzzyc_cc_module::ModuleParser;

constexpr size_t kUnwantedTokenTypes[] = {
    ModuleLexer::COMMENT, ModuleLexer::LINE_COMMENT, ModuleLexer::WHITESPACE,
    ModuleLexer::EOF};

bool IsUnwantedToken(antlr4::Token *token) {
  return (std::find(std::begin(kUnwantedTokenTypes),
                    std::end(kUnwantedTokenTypes),
                    token->getType()) != std::end(kUnwantedTokenTypes));
}

void SetTokens(antlr4::BufferedTokenStream &token_stream, size_t start,
               size_t stop, std::vector<std::string> &tokens) {
  for (auto token : token_stream.getTokens(start, stop)) {
    if (!IsUnwantedToken(token)) {
      tokens.push_back(token->getText());
    }
  }
}

}  // namespace

void LineChunk::AddToken(antlr4::Token *token) {
  if (IsUnwantedToken(token)) {
    return;
  }
  size_t line = token->getLine();
  if (!tokens_.count(line)) {
    tokens_[line] = std::vector<std::string>();
  }
  tokens_[line].push_back(token->getText());
}

void FunctionAnalyzer::enterDeclarator(FunctionParser::DeclaratorContext *ctx) {
  chunk_->local_variables_.push_back(ctx->identifier()->getText());
}

void FunctionAnalyzer::enterFuncCall(FunctionParser::FuncCallContext *ctx) {
  const auto postfix_expression = ctx->postfix_expression();
  if (postfix_expression == nullptr) {
    return;
  }
  const auto primary_expression =
      postfix_expression
          ->getRuleContext<FunctionParser::Primary_expressionContext>(0);
  if (primary_expression && primary_expression->identifier()) {
    chunk_->called_functions_.push_back(
        primary_expression->identifier()->getText());
  }
}

void FunctionAnalyzer::enterType_name(FunctionParser::Type_nameContext *ctx) {
  std::vector<antlr4::Token *> tokens = token_stream_.getTokens(
      ctx->getStart()->getTokenIndex(), ctx->getStop()->getTokenIndex());
  auto text_tokens = std::make_unique<std::vector<std::string>>();
  for (auto token : tokens) {
    text_tokens->push_back(token->getText());
  }
  chunk_->used_data_types_.push_back(std::move(text_tokens));
}

void FileSplitter::enterFunction_def(ModuleParser::Function_defContext *ctx) {
  auto chunk = std::make_unique<FunctionChunk>();
  chunk->name_ = ctx->function_name()->getText();
  chunk->line_start_ = ctx->getStart()->getLine();
  chunk->line_stop_ = ctx->getStop()->getLine();
  chunks_.push_back(std::move(chunk));
  current_chunk_ = chunks_.back().get();

  SetTokens(token_stream_, ctx->getStart()->getTokenIndex(),
            ctx->getStop()->getTokenIndex(), current_chunk_->tokens_);
}

void FileSplitter::exitFunction_def(ModuleParser::Function_defContext *ctx) {
  current_chunk_ = nullptr;
}

void FileSplitter::enterReturn_type(ModuleParser::Return_typeContext *ctx) {
  if (!current_chunk_) {
    return;
  }
  std::vector<antlr4::Token *> tokens =
      token_stream_.getTokens(ctx->type_name()->getStart()->getTokenIndex(),
                              ctx->type_name()->getStop()->getTokenIndex());
  for (auto token : tokens) {
    current_chunk_->return_type_.push_back(token->getText());
  }
}

void FileSplitter::enterParameter_name(
    ModuleParser::Parameter_nameContext *ctx) {
  if (!current_chunk_) {
    return;
  }
  current_chunk_->parameters_.push_back(ctx->identifier()->getText());
}

void FileSplitter::enterCompound_statement(
    ModuleParser::Compound_statementContext *ctx) {
  if (!current_chunk_) {
    return;
  }
  // Store the function body locations but drop the surronding curly braces.
  SetTokens(token_stream_, ctx->getStart()->getTokenIndex() + 1,
            ctx->getStop()->getTokenIndex() - 1, current_chunk_->body_tokens_);
}

void FileSplitter::enterParam_decl_specifiers(
    ModuleParser::Param_decl_specifiersContext *ctx) {
  if (!current_chunk_) {
    return;
  }
  std::vector<antlr4::Token *> tokens =
      token_stream_.getTokens(ctx->type_name()->getStart()->getTokenIndex(),
                              ctx->type_name()->getStop()->getTokenIndex());
  auto data_type = std::make_unique<std::vector<std::string>>();
  for (auto token : tokens) {
    data_type->push_back(token->getText());
  }
  current_chunk_->used_data_types_.push_back(std::move(data_type));
}

std::vector<std::unique_ptr<FunctionChunk>> FileSplitter::GetFunctionChunks() {
  return std::move(chunks_);
}

// Normally this would be called for syntax errors in the input file; however
// FuzzyC was designed to not have syntax errors on malformed code, so this is
// currently not tested. Any syntax error raised is a bug and would manifest as
// console warnings.
void ErrorListener::syntaxError(
    antlr4::Recognizer* recognizer,
    antlr4::Token* offendingSymbol,
    size_t line, size_t charPositionInLine,
    const std::string &msg,
    std::exception_ptr e) {
  auto error = std::make_unique<ParseError>(
      ParseError {
          line, charPositionInLine,
          offendingSymbol ? offendingSymbol->getText() : "",
          absl::StrCat(identifier_, ": ", msg)});
  errors_.push_back(std::move(error));
}

std::vector<std::unique_ptr<ParseError>> ErrorListener::GetErrors() {
  return std::move(errors_);
}

ParserCore::ParserCore(std::string file_path) : file_path_(file_path) {}

absl::Status ParserCore::Init() {
  file_stream_.open(file_path_);
  if (!file_stream_.is_open()) {
    return absl::UnavailableError(
        absl::StrCat("Failed to open file: ", file_path_));
  }
  absl::Status status = SplitFile();
  if (status.ok()) {
    initialized_ = true;
  }
  file_stream_.close();
  return status;
}

absl::Status ParserCore::SplitFile() {
  std::unique_ptr<antlr4::ANTLRInputStream> input_stream;
  try {
    input_stream = std::make_unique<antlr4::ANTLRInputStream>(file_stream_);
  } catch (const antlr4::IllegalArgumentException& e) {
    return absl::InvalidArgumentError(e.what());
  }

  ModuleLexer module_lexer(input_stream.get());
  ErrorListener lexer_error_listener("ModuleLexer");
  module_lexer.addErrorListener(&lexer_error_listener);
  antlr4::CommonTokenStream token_stream(&module_lexer);

  ModuleParser module_parser(&token_stream);
  ErrorListener parser_error_listener("ModuleParser");
  module_parser.addErrorListener(&parser_error_listener);

  FileSplitter file_splitter(token_stream);
  ParseTreeWalker::DEFAULT.walk(&file_splitter, module_parser.code());
  function_chunks_ = file_splitter.GetFunctionChunks();

  line_chunk_ = std::make_unique<LineChunk>();
  for (auto token : token_stream.getTokens()) {
    line_chunk_->AddToken(token);
  }

  for (auto& error : lexer_error_listener.GetErrors()) {
    errors_.push_back(std::move(error));
  }
  for (auto& error : parser_error_listener.GetErrors()) {
    errors_.push_back(std::move(error));
  }
  function_chunks_available_ = true;
  line_chunks_available_ = true;
  errors_available_ = true;
  return absl::OkStatus();
}

void ParserCore::AnalyzeChunk(FunctionChunk *chunk) {
  antlr4::ANTLRInputStream chunk_input_stream(
      absl::StrJoin(chunk->body_tokens_, " "));
  FunctionLexer chunk_lexer(&chunk_input_stream);
  ErrorListener lexer_error_listener("FunctionLexer");
  chunk_lexer.addErrorListener(&lexer_error_listener);
  antlr4::CommonTokenStream chunk_token_stream(&chunk_lexer);

  FunctionParser chunk_parser(&chunk_token_stream);
  ErrorListener parser_error_listener("FunctionParser");
  chunk_parser.addErrorListener(&parser_error_listener);
  FunctionAnalyzer chunk_analyzer(chunk_token_stream, chunk);
  ParseTreeWalker::DEFAULT.walk(&chunk_analyzer, chunk_parser.statements());

  for (auto& error : lexer_error_listener.GetErrors()) {
    errors_.push_back(std::move(error));
  }
  for (auto& error : parser_error_listener.GetErrors()) {
    errors_.push_back(std::move(error));
  }
}

absl::StatusOr<std::vector<std::unique_ptr<FunctionChunk>>>
ParserCore::GetFunctionChunks(
    std::vector<std::pair<size_t, size_t>> affected_line_ranges) {
  if (!initialized_) {
    return absl::InternalError("ParserCore is not initialized.");
  }
  if (!function_chunks_available_) {
    return absl::UnavailableError("Function Chunks are already consumed.");
  }
  std::vector<std::unique_ptr<FunctionChunk>> analyzed_chunks;
  for (std::unique_ptr<FunctionChunk> &chunk : function_chunks_) {
    if (!IsFunctionChunkAffected(
            {chunk->line_start_, chunk->line_stop_}, affected_line_ranges)) {
      continue;
    }
    AnalyzeChunk(chunk.get());
    analyzed_chunks.push_back(std::move(chunk));
  }
  function_chunks_available_ = false;
  return analyzed_chunks;
}

absl::StatusOr<std::vector<std::unique_ptr<ParseError>>>
ParserCore::GetParseErrors() {
  if (!initialized_) {
    return absl::InternalError("ParserCore is not initialized.");
  }
  if (!errors_available_) {
    return absl::UnavailableError("Parse Errors are already consumed.");
  }
  errors_available_ = false;
  return std::move(errors_);
}

bool ParserCore::IsFunctionChunkAffected(
    std::pair<size_t, size_t> chunk_line_range,
    std::vector<std::pair<size_t, size_t>> affected_line_ranges) const {
  if (affected_line_ranges.empty()) {
    return true;  // If affected ragnes are not defined, regard as affected.
  }

  for (auto range : affected_line_ranges) {
    if (range.first <= chunk_line_range.second &&
        range.second >= chunk_line_range.first) {
      return true;
    }
  }
  return false;
}

absl::StatusOr<std::unique_ptr<LineChunk>> ParserCore::GetLineChunk() {
  if (!initialized_) {
    return absl::InternalError("ParserCore is not initialized.");
  }
  if (!line_chunks_available_) {
    return absl::UnavailableError("Line Chunk is already consumed.");
  }
  line_chunks_available_ = false;
  return std::move(line_chunk_);
}

}  // namespace cpp_parser
}  // namespace vanir
