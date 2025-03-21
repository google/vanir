// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include "vanir/language_parsers/java/parser_core.h"

#include <cstddef>

#include <fstream>
#include <memory>
#include <tuple>
#include <variant>
#include <vector>
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "vanir/language_parsers/java/JavaLexer.h"
#include "vanir/language_parsers/java/JavaParser.h"

namespace vanir {
namespace java_parser {

namespace {

using ::java_cc_lexer::JavaLexer;

// Token types that we don't care about and utility function to filter them out.
constexpr size_t kUnwantedTokenTypes[] = {
  JavaLexer::COMMENT, JavaLexer::LINE_COMMENT, JavaLexer::WS, JavaLexer::EOF};
bool IsUnwantedToken(antlr4::Token *token) {
  return (std::find(std::begin(kUnwantedTokenTypes),
                    std::end(kUnwantedTokenTypes),
                    token->getType()) != std::end(kUnwantedTokenTypes));
}

// Checks whether at least one number from |start| to |end| appear in |ranges|
bool overlap(
    size_t start, size_t end,
    const std::vector<std::pair<size_t, size_t>>& ranges) {
  for (auto range : ranges) {
    if ((start <= range.second) && (end >= range.first)) {
      return true;
    }
  }
  return false;
}

}  // namespace

std::unique_ptr<FunctionChunk> FileListener::ToFunctionChunk(
    std::variant<JavaParser::MethodDeclarationContext*,
                 JavaParser::ConstructorDeclarationContext*> ctx) {
  auto chunk = std::make_unique<FunctionChunk>();

  // extract method identifier name, or class name in case of a constructor
  chunk->name_ = std::visit(
      [](const auto& var_ctx) -> std::string {
        return var_ctx->identifier()->getText(); },
      ctx);

  // extract return type, which only applies to MethodDeclarationContext
  if (std::holds_alternative<JavaParser::MethodDeclarationContext*>(ctx)) {
    const auto typeType =
        std::get<JavaParser::MethodDeclarationContext*>(ctx)->typeTypeOrVoid();
    for (auto token : token_stream_.getTokens(typeType->start->getTokenIndex(),
                                             typeType->stop->getTokenIndex())) {
      if (!IsUnwantedToken(token)) {
        chunk->return_type_.push_back(token->getText());
      }
    }
  }

  // extract parameters
  auto formal_parameters = std::visit(
      [](const auto& var_ctx) -> JavaParser::FormalParametersContext* {
        return var_ctx->formalParameters(); },
      ctx);
  auto formal_param_list = formal_parameters->formalParameterList();
  if (formal_param_list) {
    for (auto param : formal_param_list->formalParameter()) {
      chunk->parameters_.push_back(param->variableDeclaratorId()->getText());
    }
    auto last_param = formal_param_list->lastFormalParameter();
    if (last_param) {
      chunk->parameters_.push_back(
          last_param->variableDeclaratorId()->getText());
    }
  }

  // extract tokens
  auto start_token = std::visit(
      [](auto&& var_ctx) -> antlr4::Token* { return var_ctx->start; }, ctx);
  auto stop_token = std::visit(
      [](auto&& var_ctx) -> antlr4::Token* { return var_ctx->stop; }, ctx);
  for (auto token : token_stream_.getTokens(start_token->getTokenIndex(),
                                           stop_token->getTokenIndex())) {
    if (!IsUnwantedToken(token)) {
      chunk->tokens_.push_back(token->getText());
    }
  }

  chunk->line_start_ = start_token->getLine();
  chunk->line_stop_ = stop_token->getLine();
  chunk->start_token_idx_ = start_token->getTokenIndex();
  chunk->stop_token_idx_ = stop_token->getTokenIndex();

  return chunk;
}

ParserCore::ParserCore(std::string file_path) {
  file_path_ = file_path;
}

absl::StatusOr<std::tuple<
    std::vector<std::unique_ptr<FunctionChunk>>,
    std::unique_ptr<LineChunk>,
    std::vector<std::unique_ptr<ParseError>>
>>
ParserCore::Parse(
    std::vector<std::pair<size_t, size_t>> affected_line_ranges_for_functions) {
  std::ifstream file_stream(file_path_);
  if (!file_stream.is_open()) {
    return absl::UnavailableError(
        absl::StrCat("Failed to open: ", file_path_));
  }

  ErrorListener lexer_error_listener("JavaLexer");
  antlr4::ANTLRInputStream input_stream(file_stream);
  JavaLexer java_lexer(&input_stream);
  java_lexer.removeErrorListeners();  // Remove default logger error listener
  java_lexer.addErrorListener(&lexer_error_listener);

  ErrorListener parser_error_listener("JavaParser");
  antlr4::CommonTokenStream token_stream(&java_lexer);
  JavaParser parser(&token_stream);
  parser.removeErrorListeners();  // Remove default logger error listener
  parser.addErrorListener(&parser_error_listener);
  auto code_tree = parser.compilationUnit();
  FileListener listener(token_stream, affected_line_ranges_for_functions);
  antlr4::tree::ParseTreeWalker::DEFAULT.walk(&listener, code_tree);

  auto line_chunk = std::make_unique<LineChunk>();
  for (auto token : token_stream.getTokens()) {
    if (!IsUnwantedToken(token)) {
      size_t line = token->getLine();
      if (!line_chunk->tokens_.count(line)) {
        line_chunk->tokens_[line] = std::vector<std::string>();
      }
      line_chunk->tokens_[line].push_back(token->getText());
    }
  }

  std::vector<std::unique_ptr<ParseError>> errors;
  errors.reserve(lexer_error_listener.errors_.size());
  for (auto &error : lexer_error_listener.errors_) {
    errors.push_back(std::move(error));
  }
  for (auto &error : parser_error_listener.errors_) {
    errors.push_back(std::move(error));
  }

  return std::make_tuple(
      listener.GetFunctionChunks(), std::move(line_chunk), std::move(errors));
}

void FileListener::enterMethodDeclaration(
    JavaParser::MethodDeclarationContext* ctx) {
  chunks_stack_.push(ToFunctionChunk(ctx));
}

void FileListener::enterConstructorDeclaration(
    JavaParser::ConstructorDeclarationContext* ctx) {
  chunks_stack_.push(ToFunctionChunk(ctx));
}

void FileListener::exitMethodDeclaration(
    JavaParser::MethodDeclarationContext* ctx) {
  PopChunk(ctx->start->getTokenIndex(), ctx->stop->getTokenIndex());
}

void FileListener::exitConstructorDeclaration(
    JavaParser::ConstructorDeclarationContext* ctx) {
  PopChunk(ctx->start->getTokenIndex(), ctx->stop->getTokenIndex());
}

void FileListener::enterTypeType(JavaParser::TypeTypeContext* ctx) {
  if (chunks_stack_.empty())
    return;

  size_t stop = ctx->stop->getTokenIndex();
  if (stop <= last_type_token_stop_idx_)
    return;

  auto tokens = token_stream_.getTokens(ctx->start->getTokenIndex(), stop);
  std::vector<std::string> tokens_text;
  tokens_text.reserve(tokens.size());
  for (auto token : tokens) {
    if (!IsUnwantedToken(token)) {
      tokens_text.push_back(token->getText());
    }
  }
  chunks_stack_.top()->used_data_types_.push_back(std::move(tokens_text));
  last_type_token_stop_idx_ = stop;
}

void FileListener::enterLocalVariableDeclaration(
    JavaParser::LocalVariableDeclarationContext* ctx) {
  if (!chunks_stack_.empty()) {
    // a localVariableDeclaration can either be `VAR identifier = expression`...
    if (ctx->identifier()) {
      chunks_stack_.top()->local_variables_.push_back(
          ctx->identifier()->getText());
    // ... or `typeType variableDeclarators`
    } else {
      for (auto declarator : ctx->variableDeclarators()->variableDeclarator()) {
        auto var = declarator->variableDeclaratorId()->identifier()->getText();
        chunks_stack_.top()->local_variables_.push_back(var);
      }
    }
  }
}

void FileListener::enterMethodCall(JavaParser::MethodCallContext* ctx) {
  if (!chunks_stack_.empty()) {
    if (ctx->identifier()) {
      chunks_stack_.top()->called_functions_.push_back(
          ctx->identifier()->getText());
    }
    
    // because we don't want Vanir normalizer to normallize these as other
    // generic FUNCCALL's. Needs more investigation to know whether we should.
  }
}

void FileListener::enterCreator(JavaParser::CreatorContext* ctx) {
  if (!chunks_stack_.empty()) {
    if (ctx->createdName()) {
      chunks_stack_.top()->called_functions_.push_back(
          ctx->createdName()->getText());
    }
  }
}

void FileListener::PopChunk(size_t start_token_idx, size_t stop_token_idx) {
  CHECK(!chunks_stack_.empty());
  auto chunk = std::move(chunks_stack_.top());

  CHECK_EQ(chunk->start_token_idx_, start_token_idx);
  CHECK_EQ(chunk->stop_token_idx_, stop_token_idx);
  if (function_line_ranges_.empty() ||
      overlap(chunk->line_start_, chunk->line_stop_, function_line_ranges_)) {
    function_chunks_.push_back(std::move(chunk));
  }
  chunks_stack_.pop();
}

std::vector<std::unique_ptr<FunctionChunk>> FileListener::GetFunctionChunks() {
  return std::move(function_chunks_);
}

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

}  // namespace java_parser
}  // namespace vanir
