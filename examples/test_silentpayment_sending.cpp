/*
 * Test example for Silent Payment sending functionality
 * Based on BIP-352 reference implementation:
 * https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py Test
 * vectors from:
 * https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json
 */

#include <nunchuk.h>
#include <utils/silentpayment.hpp>
#include <utils/json.hpp>
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <fstream>
#include <sstream>
#include <map>
#include <set>

using namespace nunchuk;
using json = nlohmann::json;

// Helper function to convert hex string to bytes
std::vector<unsigned char> HexToBytes(const std::string& hex) {
  std::vector<unsigned char> bytes;
  for (size_t i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    unsigned char byte =
        static_cast<unsigned char>(strtoul(byteString.c_str(), nullptr, 16));
    bytes.push_back(byte);
  }
  return bytes;
}

// Helper function to convert bytes to hex string
std::string BytesToHex(const std::vector<unsigned char>& bytes) {
  std::ostringstream oss;
  for (unsigned char byte : bytes) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
  }
  return oss.str();
}

std::string BytesToHex(const uint256& hash) {
  std::ostringstream oss;
  for (int i = 0; i < 32; i++) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(hash.begin()[i]);
  }
  return oss.str();
}

// Helper function to print hex
void PrintHex(const std::vector<unsigned char>& data,
              const std::string& label = "") {
  if (!label.empty()) {
    std::cout << label << ": ";
  }
  std::cout << BytesToHex(data) << std::endl;
}

// Parse hex string to CPubKey
CPubKey ParsePubKey(const std::string& hex) {
  auto bytes = HexToBytes(hex);
  return CPubKey(bytes);
}

// Parse hex string to CKey
CKey ParsePrivKey(const std::string& hex) {
  auto bytes = HexToBytes(hex);
  CKey key;
  key.Set(bytes.begin(), bytes.end(), true);
  return key;
}

// Parse hex string to uint256
uint256 ParseUint256(const std::string& hex) {
  uint256 result;
  auto bytes = HexToBytes(hex);
  if (bytes.size() == 32) {
    memcpy(result.begin(), bytes.data(), 32);
  }
  return result;
}

// Create UnspentOutput from JSON
UnspentOutput CreateUnspentOutput(const json& vin) {
  UnspentOutput utxo;
  std::string txid = vin["txid"];
  uint32_t vout = vin["vout"];

  utxo.set_txid(txid);
  utxo.set_vout(vout);

  return utxo;
}

// Test with BIP-352 test vectors
bool TestWithVectors(const std::string& json_file_path) {
  std::cout << "=== Testing with BIP-352 Test Vectors ===\n\n";

  // Read JSON file
  std::ifstream file(json_file_path);
  if (!file.is_open()) {
    std::cerr << "Error: Cannot open file " << json_file_path << std::endl;
    return false;
  }

  json test_vectors;
  try {
    file >> test_vectors;
  } catch (const json::parse_error& e) {
    std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    return false;
  }

  if (!test_vectors.is_array()) {
    std::cerr << "Error: Test vectors should be an array" << std::endl;
    return false;
  }

  int test_count = 0;
  int pass_count = 0;
  int fail_count = 0;

  Chain chain = Chain::MAIN;  // Test vectors use mainnet addresses (sp1...)

  for (const auto& test_case : test_vectors) {
    std::string comment = test_case.value("comment", "Unknown test");
    std::cout << "Test: " << comment << std::endl;

    // Process sending tests
    if (test_case.contains("sending") && test_case["sending"].is_array()) {
      for (const auto& sending_test : test_case["sending"]) {
        test_count++;

        const auto& given = sending_test["given"];
        const auto& expected = sending_test["expected"];

        // Extract inputs
        std::vector<CKey> input_privkeys;
        std::vector<CPubKey> input_pubkeys;
        std::vector<UnspentOutput> inputs;
        std::vector<bool> is_taproot_inputs;  // Track which inputs are taproot
        
        for (const auto& vin : given["vin"]) {
          // Parse private key
          std::string privkey_hex = vin["private_key"];
          CKey privkey = ParsePrivKey(privkey_hex);
          if (!privkey.IsValid()) {
            std::cerr << "  ERROR: Invalid private key" << std::endl;
            fail_count++;
            continue;
          }
          input_privkeys.push_back(privkey);
          
          // Get public key from private key
          CPubKey pubkey = privkey.GetPubKey();
          input_pubkeys.push_back(pubkey);
          
          // Check if this is a taproot input by examining prevout scriptPubKey
          // Taproot (P2TR) scriptPubKey starts with 0x51 0x20 (OP_1 0x20)
          bool is_taproot = false;
          if (vin.contains("prevout") && vin["prevout"].contains("scriptPubKey")) {
            std::string script_hex = vin["prevout"]["scriptPubKey"]["hex"];
            // P2TR starts with 5120 (OP_1 = 0x51, push 32 bytes = 0x20)
            if (script_hex.length() >= 4 && script_hex.substr(0, 4) == "5120") {
              is_taproot = true;
            }
          }
          is_taproot_inputs.push_back(is_taproot);
          
          // Create UnspentOutput with txid and vout
          UnspentOutput utxo = CreateUnspentOutput(vin);
          inputs.push_back(utxo);
        }

        // Extract recipients
        std::vector<std::string> recipient_addresses;
        std::vector<CPubKey> B_scan_keys;
        std::vector<CPubKey> B_m_keys;

        for (const auto& recipient : given["recipients"]) {
          std::string address = recipient["address"];
          recipient_addresses.push_back(address);

          // Decode address to get B_scan and B_m
          silentpayment::SilentPaymentKeys keys =
              silentpayment::DecodeSilentPaymentAddress(address, chain);
          if (!keys.IsValid()) {
            std::cerr << "  ERROR: Failed to decode address " << address
                      << std::endl;
            fail_count++;
            continue;
          }

          B_scan_keys.push_back(keys.B_scan);
          B_m_keys.push_back(keys.B_m);

          // Verify scan_pub_key and spend_pub_key match
          std::string expected_scan = recipient["scan_pub_key"];
          std::string expected_spend = recipient["spend_pub_key"];

          CPubKey expected_scan_key = ParsePubKey(expected_scan);
          CPubKey expected_spend_key = ParsePubKey(expected_spend);

          if (keys.B_scan != expected_scan_key) {
            std::cerr << "  WARNING: B_scan mismatch for address " << address
                      << std::endl;
          }
          if (keys.B_m != expected_spend_key) {
            std::cerr << "  WARNING: B_m mismatch for address " << address
                      << std::endl;
          }
        }

        // Verify input public keys match expected
        if (expected.contains("input_pub_keys")) {
          const auto& expected_pubkeys = expected["input_pub_keys"];
          if (expected_pubkeys.is_array() &&
              expected_pubkeys.size() == input_pubkeys.size()) {
            for (size_t i = 0; i < input_pubkeys.size(); i++) {
              CPubKey expected_pubkey = ParsePubKey(expected_pubkeys[i]);
              if (input_pubkeys[i] != expected_pubkey) {
                std::cerr << "  WARNING: Input pubkey " << i << " mismatch"
                          << std::endl;
              }
            }
          }
        }

        std::cout << "  Inputs: " << input_privkeys.size() << std::endl;
        std::cout << "  Recipients: " << recipient_addresses.size()
                  << std::endl;

        // Check if we can at least verify the address encoding/decoding
        bool address_test_passed = true;
        for (size_t i = 0; i < recipient_addresses.size(); i++) {
          std::string address = recipient_addresses[i];
          silentpayment::SilentPaymentKeys decoded =
              silentpayment::DecodeSilentPaymentAddress(address, chain);
          if (!decoded.IsValid()) {
            std::cerr << "  FAIL: Address decode failed for " << address
                      << std::endl;
            address_test_passed = false;
            fail_count++;
            break;
          }

          // Re-encode and verify
          std::string reencoded = silentpayment::EncodeSilentPaymentAddress(
              decoded.B_scan, decoded.B_m, chain);
          if (reencoded != address) {
            std::cerr << "  FAIL: Address re-encode mismatch" << std::endl;
            std::cerr << "    Original: " << address << std::endl;
            std::cerr << "    Reencoded: " << reencoded << std::endl;
            address_test_passed = false;
            fail_count++;
            break;
          }
        }

        if (address_test_passed) {
          std::cout << "  PASS: Address encoding/decoding" << std::endl;
        }

        // Test full output derivation if we have proper inputs
        if (inputs.size() == input_privkeys.size() && !inputs.empty()) {
          bool output_test_passed = true;

          // Group recipients by B_scan (as per BIP-352)
          std::map<CPubKey, std::vector<CPubKey>> silent_payment_groups;
          for (size_t i = 0; i < B_scan_keys.size(); i++) {
            silent_payment_groups[B_scan_keys[i]].push_back(B_m_keys[i]);
          }

          // Derive outputs for each group
          // According to BIP-352: shared_secret is calculated once per B_scan group,
          // and k increments across all B_m values in the group
          std::vector<std::string> derived_outputs;
          for (const auto& [B_scan, B_m_list] : silent_payment_groups) {
            // Derive outputs for all B_m in this group with k incrementing
            // We need to call DeriveSilentPaymentOutputs for each B_m, but ensure
            // that k increments across all B_m. Since DeriveSilentPaymentOutputs
            // calculates shared_secret each time, we need to handle this differently.
            // Actually, looking at the reference, it calculates shared_secret once
            // and then for each B_m, it uses k=0, k=1, etc.
            // But our function DeriveSilentPaymentOutputs takes one B_m and num_outputs.
            // For multiple B_m with same B_scan, we need to call it with num_outputs=1
            // for each B_m, but the k should increment. However, each call recalculates
            // shared_secret and starts from k=0.
            // 
            // The correct approach: For each B_m, we need to derive with k starting
            // from the cumulative count of previous B_m in the same group.
            // But our current API doesn't support this.
            //
            // Let's check the reference again: it groups by B_scan, calculates
            // shared_secret once, then for each B_m, it uses k=0, k=1, etc.
            // So if we have 3 B_m with same B_scan, we get outputs with k=0, k=1, k=2.
            //
            // Our current implementation: DeriveSilentPaymentOutputs(B_scan, B_m, ..., num_outputs)
            // calculates shared_secret and then generates num_outputs outputs with k=0..num_outputs-1.
            //
            // For the test case with multiple B_m and same B_scan, we should:
            // - Call DeriveSilentPaymentOutputs once with the first B_m and num_outputs = B_m_list.size()
            // - But that would generate multiple outputs for the same B_m, not one per B_m.
            //
            // Actually, I think the issue is that we need to modify the logic to:
            // For each B_m in the group, derive 1 output, but k should increment across the group.
            // Since we can't easily modify the shared_secret calculation to be reused,
            // let's try a different approach: call DeriveSilentPaymentOutputs for each B_m
            // with num_outputs=1, and it should work if the shared_secret calculation is correct.
            // But wait, the reference shows k increments: k=0 for first B_m, k=1 for second, etc.
            //
            // I think the real issue is that when we have multiple B_m with same B_scan,
            // we should calculate shared_secret once, then for each B_m, use k=0, k=1, etc.
            // But our function doesn't support this directly.
            //
            // Let me check the test output again. The issue is that we're getting duplicate outputs.
            // This suggests that when we call DeriveSilentPaymentOutputs for each B_m with num_outputs=1,
            // we're getting the same output (k=0) for each B_m.
            //
            // The fix: We need to modify DeriveSilentPaymentOutputs to accept a starting k value,
            // OR we need to modify the test to call it differently.
            //
            // Actually, looking at the reference code more carefully:
            // ```python
            // for B_scan, B_m_values in silent_payment_groups.items():
            //     ecdh_shared_secret = input_hash * a_sum * B_scan
            //     k = 0
            //     for B_m in B_m_values:
            //         t_k = TaggedHash("BIP0352/SharedSecret", ecdh_shared_secret.get_bytes(False) + ser_uint32(k))
            //         P_km = B_m + t_k * G
            //         outputs.append(P_km.get_bytes().hex())
            //         k += 1
            // ```
            //
            // So shared_secret is calculated once per B_scan group, and k increments for each B_m.
            // Our current implementation calculates shared_secret each time, which is fine,
            // but we need to ensure k increments. Since we can't easily pass a starting k,
            // we need to modify the function or the test.
            //
            // The simplest fix: Modify the test to call DeriveSilentPaymentOutputs with
            // num_outputs = B_m_list.size() for the first B_m, then extract the outputs.
            // But that would generate multiple outputs for the same B_m, not one per B_m.
            //
            // Actually, I realize the issue: In BIP-352, when you have multiple recipients
            // with the same B_scan, you calculate shared_secret once, then for each B_m,
            // you use k=0, k=1, etc. But each B_m is different, so P_km = B_m + t_k * G
            // will be different for each B_m even with the same k.
            //
            // So the correct approach is: For each B_m, call DeriveSilentPaymentOutputs
            // with num_outputs=1, and it should use k=0. But then k should increment
            // across B_m in the same group. Since we can't easily do this with the current API,
            // we need to either:
            // 1. Modify DeriveSilentPaymentOutputs to accept a starting k
            // 2. Create a new function that handles multiple B_m with same B_scan
            // 3. Modify the test to work around this limitation
            //
            // For now, let's try option 3: Call DeriveSilentPaymentOutputs for each B_m
            // with num_outputs=1, and see if it works. If not, we'll need to modify the function.
            
            // Actually, wait. Let me re-read the reference. It shows:
            // - Group by B_scan
            // - For each group, calculate shared_secret once
            // - For each B_m in the group, calculate output with k incrementing
            //
            // So if we have B_scan1 with [B_m1, B_m2, B_m3]:
            // - shared_secret = input_hash * a_sum * B_scan1
            // - output1 = B_m1 + t_0 * G where t_0 = TaggedHash(shared_secret || 0)
            // - output2 = B_m2 + t_1 * G where t_1 = TaggedHash(shared_secret || 1)
            // - output3 = B_m3 + t_2 * G where t_2 = TaggedHash(shared_secret || 2)
            //
            // Our current function: DeriveSilentPaymentOutputs(B_scan, B_m, ..., num_outputs)
            // - Calculates shared_secret = input_hash * a_sum * B_scan
            // - For k=0 to num_outputs-1: output_k = B_m + t_k * G
            //
            // So if we call it for B_m1 with num_outputs=1, we get output with k=0.
            // If we call it for B_m2 with num_outputs=1, we get output with k=0 again (wrong!).
            //
            // The fix: We need to modify the function to accept a starting_k parameter,
            // OR we need to create a wrapper that handles multiple B_m correctly.
            //
            // For now, let's create a helper function or modify the test to work correctly.
            // Actually, the simplest fix is to modify DeriveSilentPaymentOutputs to accept
            // an optional starting_k parameter (default 0).
            
            // For each B_m in the group, derive 1 output with k incrementing
            size_t k_offset = 0;
            for (size_t i = 0; i < B_m_list.size(); i++) {
              auto outputs = silentpayment::DeriveSilentPaymentOutputs(
                  B_scan, B_m_list[i], input_privkeys, input_pubkeys, inputs,
                  is_taproot_inputs, 1, k_offset);
              if (!outputs.empty()) {
                // Convert x-only pubkey to hex string (32 bytes)
                std::vector<unsigned char> pubkey_bytes(outputs[0].begin(),
                                                        outputs[0].end());
                std::string output_hex = BytesToHex(pubkey_bytes);
                derived_outputs.push_back(output_hex);
              }
              k_offset++;
            }
          }

          // Compare with expected outputs
          if (expected.contains("outputs") && expected["outputs"].is_array()) {
            const auto& expected_outputs = expected["outputs"];
            // Expected outputs is an array of arrays (different orderings)
            bool found_match = false;
            for (const auto& expected_set : expected_outputs) {
              if (expected_set.is_array() &&
                  expected_set.size() == derived_outputs.size()) {
                std::set<std::string> expected_set_str;
                std::set<std::string> derived_set_str(derived_outputs.begin(),
                                                      derived_outputs.end());

                for (const auto& out : expected_set) {
                  if (out.is_string()) {
                    expected_set_str.insert(out.get<std::string>());
                  }
                }

                if (expected_set_str == derived_set_str) {
                  found_match = true;
                  break;
                }
              }
            }

            if (found_match) {
              std::cout << "  PASS: Output derivation matches expected"
                        << std::endl;
              pass_count++;
            } else {
              std::cerr << "  FAIL: Output derivation mismatch" << std::endl;
              std::cerr << "    Derived: ";
              for (const auto& out : derived_outputs) {
                std::cerr << out << " ";
              }
              std::cerr << std::endl;
              std::cerr << "    Expected (first set): ";
              if (!expected_outputs.empty() && expected_outputs[0].is_array()) {
                for (const auto& out : expected_outputs[0]) {
                  if (out.is_string()) {
                    std::cerr << out.get<std::string>() << " ";
                  }
                }
              }
              std::cerr << std::endl;
              output_test_passed = false;
              fail_count++;
            }
          } else {
            std::cout << "  NOTE: No expected outputs to compare" << std::endl;
          }
        } else {
          std::cout
              << "  NOTE: Skipping output derivation (inputs not properly set)"
              << std::endl;
        }

        std::cout << std::endl;
      }
    }
  }

  std::cout << "\n=== Test Summary ===" << std::endl;
  std::cout << "Total tests: " << test_count << std::endl;
  std::cout << "Passed: " << pass_count << std::endl;
  std::cout << "Failed: " << fail_count << std::endl;

  return fail_count == 0;
}

int main(int argc, char* argv[]) {
  Utils::SetChain(Chain::MAIN);

  std::cout << "Silent Payment Sending Test\n";
  std::cout << "===========================\n\n";

  try {
    // If JSON file path provided, test with vectors
    if (argc > 1) {
      std::string json_file = argv[1];
      bool success = TestWithVectors(json_file);
      return success ? 0 : 1;
    } else {
      std::cout << "Usage: " << argv[0] << " <path_to_test_vectors.json>"
                << std::endl;
      std::cout << "\nExample:" << std::endl;
      std::cout << "  " << argv[0] << " send_and_receive_test_vectors.json"
                << std::endl;
      std::cout << "\nOr download from:" << std::endl;
      std::cout << "  "
                   "https://raw.githubusercontent.com/bitcoin/bips/master/"
                   "bip-0352/send_and_receive_test_vectors.json"
                << std::endl;
      return 1;
    }

  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
