import 'package:bip32/bip32.dart';
import 'package:bip47/bip47.dart';
import 'package:bip39/bip39.dart' as bip39;

void main() async {
  String seedAlice =
      "response seminar brave tip suit recall often sound stick owner lottery motion";

  final node = BIP32
      .fromSeed(bip39.mnemonicToSeed(seedAlice))
      .derivePath("m/47'/0'/0'");

  final paymentCode = PaymentCode();
  await paymentCode.initFromPubKey(
      node.publicKey, node.chainCode,);

  print("payment code: $paymentCode");

}
