/*
 * Copyright 2023 Google LLC
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

#ifndef VANIR_LANGUAGE_PARSERS_CPP_PARSER_CORE_H_
#define VANIR_LANGUAGE_PARSERS_CPP_PARSER_CORE_H_

#include <cstddef>
#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "FunctionBaseListener.h"
#include "FunctionParser.h"
#include "ModuleBaseListener.h"
#include "ModuleParser.h"

namespace vanir {
namespace cpp_parser {

using ::fuzzyc_cc_function::FunctionBaseListener;
using ::fuzzyc_cc_function::FunctionParser;
using ::fuzzyc_cc_module::ModuleBaseListener;
using ::fuzzyc_cc_module::ModuleParser;

// Container for a function and its metadata extracted by parser.
class FunctionChunk {
 public:
  explicit FunctionChunk() {}

  std::string name_;
  std::vector<std::string> return_type_;
  std::vector<std::string> parameters_;
  std::vector<std::unique_ptr<std::vector<std::string>>> used_data_types_;
  std::vector<std::string> local_variables_;
  std::vector<std::string> called_functions_;
  std::vector<std::string> body_tokens_;
  std::vector<std::string> tokens_;

  size_t line_start_;
  size_t line_stop_;

 private:
  FunctionChunk(const FunctionChunk &) = delete;
  FunctionChunk(FunctionChunk &&) = delete;
  FunctionChunk &operator=(const FunctionChunk &) = delete;
  FunctionChunk &operator=(FunctionChunk &&) = delete;
};

// Container for tokenized lines extracted by parser. The lines and tokens
// having no semantic impact are excluded.
class LineChunk {
 public:
  explicit LineChunk() {}

  // Adds a lexical token to the line token map |tokens_|.
  void AddToken(antlr4::Token *token);

  // Key: line number. Value: Token list of the line.
  std::unordered_map<size_t, std::vector<std::string>> tokens_;

 private:
  LineChunk(const LineChunk &) = delete;
  LineChunk(LineChunk &&) = delete;
  LineChunk &operator=(const LineChunk &) = delete;
  LineChunk &operator=(LineChunk &&) = delete;
};

// Container for any error encountered during parsing. Each error contains the
// location and the token where the parsing error happened, as well as error
// message if any.
struct ParseError {
  size_t line, column;
  std::string bad_token;
  std::string message;
};

// Listener for ANTLR Fuzzyc Function parser.
class FunctionAnalyzer : public FunctionBaseListener {
 public:
  explicit FunctionAnalyzer(antlr4::BufferedTokenStream &tokens,
                            FunctionChunk *chunk)
      : token_stream_(tokens), chunk_(chunk) {}

  // Function parser callback for extracting local variables.
  void enterDeclarator(FunctionParser::DeclaratorContext *ctx) override;

  // Function parser callback for extracting functions called in the target
  // function.
  void enterFuncCall(FunctionParser::FuncCallContext *ctx) override;

  // Function parser callback for extracting local variable types.
  void enterType_name(FunctionParser::Type_nameContext *ctx) override;

 protected:
  antlr4::BufferedTokenStream &token_stream_;
  FunctionChunk *chunk_;
};

// Listener for ANTLR Fuzzyc Module parser.
class FileSplitter : public ModuleBaseListener {
 public:
  explicit FileSplitter(antlr4::BufferedTokenStream &tokens)
      : token_stream_(tokens) {}

  // Module parser callback for tracking start of new function definition and
  // extracting function metadata.
  void enterFunction_def(ModuleParser::Function_defContext *ctx) override;

  // Module parser callback for tracking end of function definition.
  void exitFunction_def(ModuleParser::Function_defContext *ctx) override;

  // Module parser callback for extracting function return type. Note that
  // return type does not include declaration specifiers such as 'static' and
  // 'explicit'.
  void enterReturn_type(ModuleParser::Return_typeContext *ctx) override;

  // Module parser callback for extracting function parameters.
  void enterParameter_name(ModuleParser::Parameter_nameContext *ctx) override;

  // Module parser callback for extracting function body to be further parsed by
  // Function parser.
  void enterCompound_statement(
      ModuleParser::Compound_statementContext *ctx) override;

  // Module parser callback for extracting function parameter types.
  void enterParam_decl_specifiers(
      ModuleParser::Param_decl_specifiersContext *ctx) override;

  // Returns function chunks extracted during the module parsing. The ownership
  // also transfers to the caller.
  std::vector<std::unique_ptr<FunctionChunk>> GetFunctionChunks();

 protected:
  antlr4::BufferedTokenStream &token_stream_;
  FunctionChunk *current_chunk_ = nullptr;
  std::vector<std::unique_ptr<FunctionChunk>> chunks_;
};

// Listener for errors during parsing, allowing storing and retrieval of
// ParseError objects. Error messages will have the identifier string prepended.
class ErrorListener : public antlr4::BaseErrorListener {
 public:
  // Initialize an ErrorListener object with the identifier string
  explicit ErrorListener(std::string identifier) : identifier_(identifier) {}

  void syntaxError(
      antlr4::Recognizer* recognizer,
      antlr4::Token* offendingSymbol,
      size_t line, size_t charPositionInLine,
      const std::string &msg,
      std::exception_ptr e) override;

  std::vector<std::unique_ptr<ParseError>> GetErrors();

 private:
  const std::string identifier_;
  std::vector<std::unique_ptr<ParseError>> errors_;
};

// Parses C/C++ files and extracts functions, valid lines and their metadata.
class ParserCore {
 public:
  // Instantiate Parser for the file located at |file_path|.
  explicit ParserCore(std::string file_path);

  // Opens the target file and parse it. Must be called before request for
  // chunks.
  absl::Status Init();

  // Returns functions extracted from the target file. Also transfers chunk
  // ownership.
  // If |affected_line_ranges| is empty, parse all functions in the file.
  // If |affected_line_ranges| is specified, parse only functions that has
  // at least one line in one of the ranges. Ranges are inclusive.
  // E.g., for the following file, when affected_line_ranges = {{7, 7}}
  //   5: ...
  //   6: int affected_func (void) {
  //   7:   some_function();
  //   8: }
  //   9: void unaffected_func (void) { ...
  // affected_func() will be returned but unaffected_func() will not.
  absl::StatusOr<std::vector<std::unique_ptr<FunctionChunk>>>
  GetFunctionChunks(
      std::vector<std::pair<size_t, size_t>> affected_line_ranges = {});

  // Returns valid tokenized lines extracted from the target file. Also
  // transfers chunk ownership. Note: some macro lines will be dropped by
  // Fuzzyc.
  absl::StatusOr<std::unique_ptr<LineChunk>> GetLineChunk();

  // Returns the list of errors encountered by the parser
  absl::StatusOr<std::vector<std::unique_ptr<ParseError>>> GetParseErrors();

  ParserCore(const ParserCore &) = delete;
  ParserCore &operator=(const ParserCore &) = delete;

 protected:
  // Runs the Fuzzyc Module parser against the file and split into function
  // chunks. Also stores tokenized lines in a line chunk.
  absl::Status SplitFile();

  // Runs the Fuzzyc Function parser against the function code snippet, extracts
  // function metadata and puts the data into the function chunk.
  void AnalyzeChunk(FunctionChunk *chunk);

  // Check if the given line range of a function chunk overlaps with the
  // given |affected_line_ranges|.
  bool IsFunctionChunkAffected(
      std::pair<size_t, size_t> chunk_line_range,
      std::vector<std::pair<size_t, size_t>> affected_line_ranges) const;

  std::string file_path_;
  std::ifstream file_stream_;
  std::vector<std::unique_ptr<FunctionChunk>> function_chunks_;
  std::unique_ptr<LineChunk> line_chunk_;

 private:
  bool initialized_ = false;
  bool function_chunks_available_ = false;
  bool line_chunks_available_ = false;
  bool errors_available_ = false;
  std::vector<std::unique_ptr<ParseError>> errors_;
};

}  // namespace cpp_parser
}  // namespace vanir

#endif  // VANIR_LANGUAGE_PARSERS_CPP_PARSER_CORE_H_
