#include "util.h"
#include "compiler.h"

#include <sstream>
#include <regex>
#include <cassert>
#include <nunchuk.h>
#include <vector>
#include <stdexcept>
#include <utils/stringutils.hpp>
#include <descriptor.h>

namespace nunchuk {

std::string PolicyToString(const Policy& node) {
  switch (node.node_type) {
    case Policy::Type::PK_K:
      return "pk(" + node.keys[0] + ")";
    case Policy::Type::AFTER:
      return "after(" + std::to_string(node.k) + ")";
    case Policy::Type::OLDER:
      return "older(" + std::to_string(node.k) + ")";
    case Policy::Type::HASH160:
      return "hash160(" + HexStr(node.data) + ")";
    case Policy::Type::HASH256:
      return "hash256(" + HexStr(node.data) + ")";
    case Policy::Type::RIPEMD160:
      return "ripemd160(" + HexStr(node.data) + ")";
    case Policy::Type::SHA256:
      return "sha256(" + HexStr(node.data) + ")";
    case Policy::Type::AND:
      return "and(" + PolicyToString(node.sub[0]) + "," +
             PolicyToString(node.sub[1]) + ")";
    case Policy::Type::OR:
      return "or(" + PolicyToString(node.sub[0]) + "," +
             PolicyToString(node.sub[1]) + ")";
    case Policy::Type::THRESH:
      std::stringstream ss;
      ss << "thresh(" << node.k;
      for (int i = 0; i < node.sub.size(); i++) {
        ss << "," << PolicyToString(node.sub[i]);
      }
      ss << ")";
      return ss.str();
  }
  assert(false);
  return "";
}

std::string PolicyToMiniscript(const Policy& node,
                               const std::map<std::string, std::string>& config,
                               AddressType address_type) {
  Policy policy = node.Clone();
  std::function<void(Policy&)> configure = [&](Policy& node) -> void {
    if (node.node_type == Policy::Type::OLDER ||
        node.node_type == Policy::Type::AFTER) {
      if (node.keys.size() == 1) {
        node.k = std::stoi(config.at(node.keys[0]));
      }
    } else {
      for (int i = 0; i < node.keys.size(); i++) {
        node.keys[i] = config.at(node.keys[i]);
      }
    }
    for (int i = 0; i < node.sub.size(); i++) {
      configure(node.sub[i]);
    }
  };
  configure(policy);

  double avgcost;
  miniscript::NodeRef<std::string> ret;
  if (!CompilePolicy(policy, ret, avgcost)) return "";
  std::string miniscript =
      Abbreviate(*(ret->ToString<CompilerContext>(COMPILER_CTX)));
  if (address_type == AddressType::TAPROOT) {
    miniscript =
        std::regex_replace(miniscript, std::regex("multi\\("), "multi_a(");
  }
  return miniscript;
}

miniscript::NodeRef<std::string> ParseMiniscript(const std::string& script,
                                                 AddressType address_type) {
  ParseContext ctx{miniscript::MiniscriptContext::P2WSH};
  if (address_type == AddressType::TAPROOT ||
      (address_type == AddressType::ANY &&
       script.find("multi_a(") != std::string::npos)) {
    ctx.ms_context = miniscript::MiniscriptContext::TAPSCRIPT;
  }
  return miniscript::FromString<ParseContext>(script, ctx);
}

std::string MiniscriptToString(const miniscript::NodeRef<std::string>& node) {
  return *(node->ToString<CompilerContext>(COMPILER_CTX));
}

ScriptNode MiniscriptToScriptNode(
    const miniscript::NodeRef<std::string>& node) {
  if (!node) return ScriptNode();

  std::vector<ScriptNode> subs;
  for (auto& sub : node->subs) {
    subs.push_back(MiniscriptToScriptNode(sub));
  }

  switch (node->fragment) {
    case miniscript::Fragment::PK_K:
    case miniscript::Fragment::PK_H:
      return ScriptNode(
          ScriptNode::Type::PK, std::move(subs),
          std::vector<std::string>(node->keys.begin(), node->keys.end()), {},
          node->k);
    case miniscript::Fragment::OLDER:
      return ScriptNode(ScriptNode::Type::OLDER, std::move(subs), {}, {},
                        node->k);
    case miniscript::Fragment::AFTER:
      return ScriptNode(ScriptNode::Type::AFTER, std::move(subs), {}, {},
                        node->k);
    case miniscript::Fragment::HASH160:
      return ScriptNode(
          ScriptNode::Type::HASH160, std::move(subs), {},
          std::vector<unsigned char>(node->data.begin(), node->data.end()),
          node->k);
    case miniscript::Fragment::HASH256:
      return ScriptNode(
          ScriptNode::Type::HASH256, std::move(subs), {},
          std::vector<unsigned char>(node->data.begin(), node->data.end()),
          node->k);
    case miniscript::Fragment::RIPEMD160:
      return ScriptNode(
          ScriptNode::Type::RIPEMD160, std::move(subs), {},
          std::vector<unsigned char>(node->data.begin(), node->data.end()),
          node->k);
    case miniscript::Fragment::SHA256:
      return ScriptNode(
          ScriptNode::Type::SHA256, std::move(subs), {},
          std::vector<unsigned char>(node->data.begin(), node->data.end()),
          node->k);
    case miniscript::Fragment::AND_V:
      if (node->subs[1]->fragment == miniscript::Fragment::JUST_1) {
        return std::move(subs[0]);
      }
    case miniscript::Fragment::AND_B:
      return ScriptNode(ScriptNode::Type::AND, std::move(subs), {}, {},
                        node->k);
    case miniscript::Fragment::OR_I:
      if (node->subs[0]->fragment == miniscript::Fragment::JUST_0) {
        return std::move(subs[1]);
      } else if (node->subs[1]->fragment == miniscript::Fragment::JUST_0) {
        return std::move(subs[0]);
      }
    case miniscript::Fragment::OR_B:
    case miniscript::Fragment::OR_C:
    case miniscript::Fragment::OR_D:
      return ScriptNode(ScriptNode::Type::OR, std::move(subs), {}, {}, node->k);
    case miniscript::Fragment::ANDOR:
      if (node->subs[2]->fragment == miniscript::Fragment::JUST_0) {
        return ScriptNode(ScriptNode::Type::AND, std::move(subs), {}, {},
                          node->k);
      }
      return ScriptNode(ScriptNode::Type::ANDOR, std::move(subs), {}, {},
                        node->k);
    case miniscript::Fragment::THRESH:
      return ScriptNode(
          ScriptNode::Type::THRESH, std::move(subs),
          std::vector<std::string>(node->keys.begin(), node->keys.end()), {},
          node->k);
    case miniscript::Fragment::MULTI:
    case miniscript::Fragment::MULTI_A:
      return ScriptNode(
          ScriptNode::Type::MULTI, std::move(subs),
          std::vector<std::string>(node->keys.begin(), node->keys.end()), {},
          node->k);
    case miniscript::Fragment::WRAP_A:
    case miniscript::Fragment::WRAP_S:
    case miniscript::Fragment::WRAP_C:
    case miniscript::Fragment::WRAP_D:
    case miniscript::Fragment::WRAP_V:
    case miniscript::Fragment::WRAP_J:
    case miniscript::Fragment::WRAP_N:
      if (!subs.empty()) {
        return std::move(subs[0]);
      }
      return ScriptNode();
    default:
      return ScriptNode();
  }
}

std::string ScriptNodeToString(const ScriptNode& node) {
  switch (node.get_type()) {
    case ScriptNode::Type::PK:
      return "pk(" + node.get_keys()[0] + ")";
    case ScriptNode::Type::AFTER:
      return "after(" + std::to_string(node.get_k()) + ")";
    case ScriptNode::Type::OLDER:
      return "older(" + std::to_string(node.get_k()) + ")";
    case ScriptNode::Type::HASH160:
      return "hash160(" + HexStr(node.get_data()) + ")";
    case ScriptNode::Type::HASH256:
      return "hash256(" + HexStr(node.get_data()) + ")";
    case ScriptNode::Type::RIPEMD160:
      return "ripemd160(" + HexStr(node.get_data()) + ")";
    case ScriptNode::Type::SHA256:
      return "sha256(" + HexStr(node.get_data()) + ")";
    case ScriptNode::Type::AND:
      return "and(" + ScriptNodeToString(node.get_subs()[0]) + "," +
             ScriptNodeToString(node.get_subs()[1]) + ")";
    case ScriptNode::Type::OR:
      return "or(" + ScriptNodeToString(node.get_subs()[0]) + "," +
             ScriptNodeToString(node.get_subs()[1]) + ")";
    case ScriptNode::Type::ANDOR:
      return "andor(" + ScriptNodeToString(node.get_subs()[0]) + "," +
             ScriptNodeToString(node.get_subs()[1]) + "," +
             ScriptNodeToString(node.get_subs()[2]) + ")";
    case ScriptNode::Type::THRESH: {
      std::stringstream ss;
      ss << "thresh(" << node.get_k();
      for (int i = 0; i < node.get_subs().size(); i++) {
        ss << "," << ScriptNodeToString(node.get_subs()[i]);
      }
      ss << ")";
      return ss.str();
    }
    case ScriptNode::Type::MULTI: {
      std::stringstream ss;
      ss << "multi(" << node.get_k();
      for (int i = 0; i < node.get_keys().size(); i++) {
        ss << "," << node.get_keys()[i];
      }
      ss << ")";
      return ss.str();
    }
    case ScriptNode::Type::OR_TAPROOT:
      return "{" + ScriptNodeToString(node.get_subs()[0]) + "," +
             ScriptNodeToString(node.get_subs()[1]) + "}";
    case ScriptNode::Type::MUSIG: {
      std::stringstream ss;
      ss << "pk(musig(";
      for (int i = 0; i < node.get_keys().size(); i++) {
        if (i > 0) ss << ",";
        ss << node.get_keys()[i];
      }
      ss << "))";
      return ss.str();
    }
  }
  assert(false);
  return "";
}

bool ParseTapscriptTemplate(const std::string& tapscript_template,
                            std::string& keypath,
                            std::vector<std::string>& subscripts,
                            std::vector<int>& depths, std::string& error) {
  using namespace script;
  Span<const char> expr{tapscript_template};
  if (Func("tr", expr)) {
    auto a = Expr(expr);
    keypath = std::string(a.begin(), a.end());
    if (!Const(",", expr)) {
      error = strprintf("tr: expected ',', got '%c'", expr[0]);
      return false;
    }
  }

  /** The path from the top of the tree to what we're currently processing.
   * branches[i] == false: left branch in the i'th step from the top; true:
   * right branch.
   */
  std::vector<bool> branches;
  // Loop over all provided scripts. In every iteration exactly one script
  // will be processed. Use a do-loop because inside this if-branch we expect
  // at least one script.
  do {
    // First process all open braces.
    while (Const("{", expr)) {
      branches.push_back(false);  // new left branch
      if (branches.size() > TAPROOT_CONTROL_MAX_NODE_COUNT) {
        error = strprintf("tr() supports at most %i nesting levels",
                          TAPROOT_CONTROL_MAX_NODE_COUNT);
        return false;
      }
    }
    // Process the actual script expression.
    auto sarg = Expr(expr);
    subscripts.push_back(std::string(sarg.begin(), sarg.end()));
    depths.push_back(branches.size());
    // Process closing braces
    while (branches.size() && branches.back()) {
      if (!Const("}", expr)) {
        error = strprintf("tr(): expected '}' after script expression");
        return false;
      }
      branches.pop_back();  // move up one level after encountering '}'
    }
    // If after that, we're at the end of a left branch, expect a comma.
    if (branches.size() && !branches.back()) {
      if (!Const(",", expr)) {
        error = strprintf("tr(): expected ',' after script expression");
        return false;
      }
      branches.back() = true;  // And now we're in a right branch.
    }
  } while (branches.size());
  // After we've explored a whole tree, we must be at the end of the expr.
  if (expr.size()) {
    error = strprintf("tr(): expected ')' after script expression");
    return false;
  }
  return true;
}

bool SubScriptsToString(const std::vector<std::string>& subscripts,
                        const std::vector<int>& depths, std::string& ret) {
  if (depths.empty()) return true;
  std::vector<bool> path;
  for (size_t pos = 0; pos < depths.size(); ++pos) {
    if (pos) ret += ',';
    while ((int)path.size() <= depths[pos]) {
      if (path.size()) ret += '{';
      path.push_back(false);
    }
    ret += subscripts[pos];
    while (!path.empty() && path.back()) {
      if (path.size() > 1) ret += '}';
      path.pop_back();
    }
    if (!path.empty()) path.back() = true;
  }
  return true;
}

struct TreeNode {
  std::string value;
  TreeNode* left;
  TreeNode* right;
  bool isLeaf;

  TreeNode(const std::string& val = "", bool leaf = false)
      : value(val), left(nullptr), right(nullptr), isLeaf(leaf) {}
};

ScriptNode TreeToScriptNode(TreeNode* root) {
  if (root->isLeaf) {
    if (IsValidMusigTemplate(root->value)) {
      std::string inner = root->value.substr(9, root->value.size() - 11);
      std::vector<std::string> keys = split(inner, ',');
      auto k = keys.size();
      return ScriptNode{ScriptNode::Type::MUSIG, {}, std::move(keys), {}, k};
    } else {
      return MiniscriptToScriptNode(
          ParseMiniscript(root->value, AddressType::ANY));
    }
  }
  std::vector<ScriptNode> subs;
  subs.push_back(TreeToScriptNode(root->left));
  subs.push_back(TreeToScriptNode(root->right));
  return ScriptNode{ScriptNode::Type::OR_TAPROOT, std::move(subs), {}, {}, 0};
}

ScriptNode SubScriptsToScriptNode(const std::vector<std::string>& subscripts,
                                  const std::vector<int>& depths) {
  TreeNode* root = new TreeNode("", false);
  std::vector<TreeNode*> stack;
  stack.push_back(root);

  std::vector<bool> path;
  for (size_t pos = 0; pos < depths.size(); ++pos) {
    while ((int)path.size() <= depths[pos]) {
      if (path.size()) {
        TreeNode* node = new TreeNode("", false);
        if (stack.back()->left == nullptr) {
          stack.back()->left = node;
        } else {
          stack.back()->right = node;
        }
        stack.push_back(node);
      }
      path.push_back(false);
    }

    if (stack.back()->left == nullptr) {
      stack.back()->left = new TreeNode(subscripts[pos], true);
    } else {
      stack.back()->right = new TreeNode(subscripts[pos], true);
    }
    while (!path.empty() && path.back()) {
      if (path.size() > 1) stack.pop_back();
      path.pop_back();
    }
    if (!path.empty()) path.back() = true;
  }
  auto rs = TreeToScriptNode(root->left);

  // delete tree
  while (!stack.empty()) {
    TreeNode* current = stack.back();
    stack.pop_back();
    if (current->left != nullptr) {
      stack.push_back(current->left);
    }
    if (current->right != nullptr) {
      stack.push_back(current->right);
    }
    delete current;
  }
  return rs;
}

void combinations(const std::vector<std::vector<SigningPath>>& lists,
                  int list_index, std::vector<SigningPath>& current,
                  std::vector<std::vector<SigningPath>>& result) {
  if (list_index == lists.size()) {
    result.push_back(current);
    return;
  }

  for (int i = 0; i < lists[list_index].size(); ++i) {
    current.push_back(lists[list_index][i]);
    combinations(lists, list_index + 1, current, result);
    current.pop_back();
  }
}

std::vector<SigningPath> get_all_paths(const ScriptNode& node) {
  if (node.get_type() != ScriptNode::Type::ANDOR &&
      node.get_type() != ScriptNode::Type::AND &&
      node.get_type() != ScriptNode::Type::THRESH &&
      node.get_type() != ScriptNode::Type::OR &&
      node.get_type() != ScriptNode::Type::OR_TAPROOT) {
    return {{node.get_id()}};
  }
  std::vector<SigningPath> paths;

  if (node.get_type() == ScriptNode::Type::ANDOR) {
    std::map<size_t, std::vector<SigningPath>> sub_paths;
    for (size_t i = 0; i < node.get_subs().size(); i++) {
      sub_paths[i] = get_all_paths(node.get_subs()[i]);
    }
    std::vector<std::vector<SigningPath>> xandy_paths;
    std::vector<SigningPath> current;
    combinations({sub_paths[0], sub_paths[1]}, 0, current, xandy_paths);

    for (const auto& combination : xandy_paths) {
      SigningPath sub_path;
      for (size_t i = 0; i < combination.size(); ++i) {
        sub_path.insert(sub_path.end(), combination[i].begin(),
                        combination[i].end());
      }
      paths.push_back(sub_path);
    }

    for (auto&& sub_path : sub_paths[2]) {
      paths.push_back(sub_path);
    }
  } else if (node.get_type() == ScriptNode::Type::AND ||
             node.get_type() == ScriptNode::Type::THRESH) {
    std::map<size_t, std::vector<SigningPath>> sub_paths;
    for (size_t i = 0; i < node.get_subs().size(); i++) {
      sub_paths[i] = get_all_paths(node.get_subs()[i]);
    }
    std::vector<bool> v(node.get_subs().size());
    auto k = node.get_type() == ScriptNode::Type::THRESH ? node.get_k() : 2;
    std::fill(v.begin(), v.begin() + k, true);
    do {
      std::vector<std::vector<SigningPath>> lists{};

      for (int i = 0; i < node.get_subs().size(); i++) {
        if (v[i]) {
          lists.push_back(sub_paths[i]);
        }
      }

      std::vector<std::vector<SigningPath>> result;
      std::vector<SigningPath> current;
      combinations(lists, 0, current, result);

      for (const auto& combination : result) {
        SigningPath sub_path;
        for (size_t i = 0; i < combination.size(); ++i) {
          sub_path.insert(sub_path.end(), combination[i].begin(),
                          combination[i].end());
        }
        paths.push_back(sub_path);
      }
    } while (std::prev_permutation(v.begin(), v.end()));

  } else if (node.get_type() == ScriptNode::Type::OR ||
             node.get_type() == ScriptNode::Type::OR_TAPROOT) {
    for (size_t i = 0; i <= 1; i++) {
      auto sub_paths = get_all_paths(node.get_subs()[i]);
      for (auto&& sub_path : sub_paths) {
        paths.push_back(sub_path);
      }
    }
  }
  return paths;
}

std::vector<SigningPath> GetAllSigningPaths(const ScriptNode& node) {
  return get_all_paths(node);
}

bool IsValidMusigTemplate(const std::string& musig_template) {
  if (musig_template.size() <= 11) return false;
  if (musig_template.find("pk(musig(") != 0) return false;
  if (musig_template.find("))", 9) != musig_template.size() - 2) return false;
  std::string inner = musig_template.substr(9, musig_template.size() - 11);
  std::vector<std::string> inner_parts = split(inner, ',');
  if (inner_parts.size() < 2) return false;
  if (join(inner_parts, ',') != inner) return false;
  return true;
}

std::string GetMusigScript(const std::string& musig_template,
                           const std::map<std::string, SingleSigner>& signers) {
  if (!IsValidMusigTemplate(musig_template))
    throw NunchukException(NunchukException::INVALID_PARAMETER,
                           "Invalid musig template");
  std::string inner = musig_template.substr(9, musig_template.size() - 11);
  std::vector<std::string> parts = split(inner, ',');
  std::stringstream ss;
  ss << "pk(musig(";
  for (int i = 0; i < parts.size(); i++) {
    if (i > 0) ss << ",";
    ss << GetDescriptorForSigner(signers.at(parts[i]), DescriptorPath::ANY);
  }
  ss << "))";
  return ss.str();
}

}  // namespace nunchuk