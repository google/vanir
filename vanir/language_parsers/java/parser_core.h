/*
 * Copyright 2023 Google LLC
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

#ifndef VANIR_LANGUAGE_PARSERS_JAVA_PARSER_CORE_H_
#define VANIR_LANGUAGE_PARSERS_JAVA_PARSER_CORE_H_

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "vanir/language_parsers/java/JavaParser.h"
#include "vanir/language_parsers/java/JavaParserBaseListener.h"

namespace vanir {
namespace java_parser {

using ::java_cc_parser::JavaParser;
using ::java_cc_parser::JavaParserBaseListener;

// Container for a function and its metadata extracted by the parser
class FunctionChunk {
 public:
  explicit FunctionChunk()
      : line_start_(0), line_stop_(0), start_token_idx_(0), stop_token_idx_(0)
      {}

  std::string name_;
  std::vector<std::string> return_type_;
  std::vector<std::string> parameters_;
  std::vector<std::vector<std::string>> used_data_types_;
  std::vector<std::string> local_variables_;
  std::vector<std::string> called_functions_;
  std::vector<std::string> tokens_;
  size_t line_start_, line_stop_;
  size_t start_token_idx_, stop_token_idx_;

 private:
  FunctionChunk(const FunctionChunk &) = delete;
  FunctionChunk(FunctionChunk &&) = delete;
  FunctionChunk &operator=(const FunctionChunk &) = delete;
  FunctionChunk &operator=(FunctionChunk &&) = delete;
};

// LineChunk is a wrapper class for a map from line numbers to all tokens in
// that line. This is needed instead of a simple type alias because pybind's
// automatic conversion of wrappers (e.g. unique_ptr) only supports custom
// types, and not e.g. unordered_map.
class LineChunk {
 public:
  explicit LineChunk() {}
  std::unordered_map<size_t, std::vector<std::string>> tokens_;

 private:
  LineChunk(const LineChunk &) = delete;
  LineChunk(LineChunk &&) = delete;
  LineChunk &operator=(const LineChunk &) = delete;
  LineChunk &operator=(LineChunk &&) = delete;
};

// Container for any error encountered during parsing
struct ParseError {
  size_t line, column;
  std::string bad_token;
  std::string message;
};

// Antlr4 parser tree walking listener.
class FileListener : public JavaParserBaseListener {
 public:
  explicit FileListener(
      antlr4::BufferedTokenStream &tokens,
      std::vector<std::pair<size_t, size_t>> function_line_ranges = {})
      : token_stream_(tokens), function_line_ranges_(function_line_ranges) {}

  void enterMethodDeclaration(JavaParser::MethodDeclarationContext*) override;
  void exitMethodDeclaration(JavaParser::MethodDeclarationContext*) override;
  void enterConstructorDeclaration(
      JavaParser::ConstructorDeclarationContext*) override;
  void exitConstructorDeclaration(
      JavaParser::ConstructorDeclarationContext*) override;

  void enterTypeType(JavaParser::TypeTypeContext*) override;

  void enterLocalVariableDeclaration(
      JavaParser::LocalVariableDeclarationContext*) override;

  void enterMethodCall(JavaParser::MethodCallContext*) override;
  void enterCreator(JavaParser::CreatorContext*) override;

  std::vector<std::unique_ptr<FunctionChunk>> GetFunctionChunks();

 private:
  antlr4::BufferedTokenStream &token_stream_;

  // last_type_token_stop_idx_ holds the last token in a typeType, so that we
  // can ignore all other nested typeType, e.g. `ArrayList<Object>` should only
  // manifest as a single used datatype instead of two.
  size_t last_type_token_stop_idx_ = 0;
  std::vector<std::pair<size_t, size_t>> function_line_ranges_;
  std::stack<std::unique_ptr<FunctionChunk>> chunks_stack_;
  std::vector<std::unique_ptr<FunctionChunk>> function_chunks_;

  // Helper function to collect various information bits into a FunctionChunk
  // ctx can be either a MethodDeclarationContext or a
  // ConstructorDeclarationContext, both should have all the needed information.
  std::unique_ptr<FunctionChunk> ToFunctionChunk(
      std::variant<JavaParser::MethodDeclarationContext*,
                   JavaParser::ConstructorDeclarationContext*> ctx);

  // Pops a function chunk from the chunks stack, checking to make sure the
  // function chunk being popped is the same as the one being processed, then
  // adds the chunk to the list of function_chunks_.
  void PopChunk(size_t start_token_idx, size_t stop_token_idx);
};

// Listener for errors during parsing
class ErrorListener : public antlr4::BaseErrorListener {
 public:
  explicit ErrorListener(std::string identifier) : identifier_(identifier) {}
  void syntaxError(
      antlr4::Recognizer* recognizer,
      antlr4::Token* offendingSymbol,
      size_t line, size_t charPositionInLine,
      const std::string &msg,
      std::exception_ptr e) override;

  std::vector<std::unique_ptr<ParseError>> errors_;

 private:
  const std::string identifier_;
};

// Parses Java files and extract functions, metadata, and tokens split by lines.
class ParserCore {
 public:
  // Instantiate Parser for file located at |file_path|
  explicit ParserCore(std::string file_path);

  // Parses the given file and returns a list of function chunks and tokens map
  // split by lines.
  // If |affected_line_ranges_for_functions| is empty, parses all functions.
  // Otherwise, parse, only the functions that has at least one line in one of
  // the ranges. Ranges are inclusive.
  absl::StatusOr<std::tuple<
      std::vector<std::unique_ptr<FunctionChunk>>,
      std::unique_ptr<LineChunk>,
      std::vector<std::unique_ptr<ParseError>>
  >>
  Parse(std::vector<std::pair<size_t, size_t>>
        affected_line_ranges_for_functions = {});

 private:
  std::string file_path_;
};

}  // namespace java_parser
}  // namespace vanir

#endif  // VANIR_LANGUAGE_PARSERS_JAVA_PARSER_CORE_H_
