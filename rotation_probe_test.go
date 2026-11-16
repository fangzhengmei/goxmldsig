package dsig

// 探针：实证 verifyCertificate/Validate 在 SSO 证书轮换窗口各时刻的匹配语义。
// 运行: go test -run TestRotationProbe -v .

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
)

type probeKeyStore struct {
	key  *rsa.PrivateKey
	cert []byte
}

func (ks *probeKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.key, ks.cert, nil
}

func mkCert(t *testing.T, cn string, key *rsa.PrivateKey, serial int64, nb, na time.Time, issuer *x509.Certificate, issuerKey *rsa.PrivateKey) ([]byte, *x509.Certificate) {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if issuer == nil {
		issuer = tpl
		issuerKey = key
		tpl.KeyUsage |= x509.KeyUsageCertSign
		tpl.IsCA = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, cert
}

func signProbeDoc(t *testing.T, key *rsa.PrivateKey, certDER []byte) *etree.Document {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<root ID="_probe1"><child>payload</child></root>`); err != nil {
		t.Fatal(err)
	}
	ctx := NewDefaultSigningContext(&probeKeyStore{key: key, cert: certDER})
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	tmp := etree.NewDocument()
	tmp.SetRoot(signed)
	// 注意：SignEnveloped 直接 append 子节点导致 etree 索引失效，
	// 必须重序列化-解析后再 Validate（见报告"缺口"一节）。
	s, err := tmp.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	if err := out.ReadFromString(s); err != nil {
		t.Fatal(err)
	}
	return out
}

func stripKeyInfo(doc *etree.Document) {
	sig := doc.FindElement("//" + SignatureTag)
	ki := sig.FindElement("./" + DefaultPrefix + ":" + KeyInfoTag)
	if ki == nil { // 签名前缀可能是默认 ds
		ki = sig.FindElement("./" + KeyInfoTag)
	}
	sig.RemoveChild(ki)
}

func tryValidate(doc *etree.Document, roots []*x509.Certificate, at *time.Time) error {
	store := &MemoryX509CertificateStore{Roots: roots}
	vc := NewDefaultValidationContext(store)
	if at != nil {
		vc.Clock = NewFakeClockAt(*at)
	}
	_, err := vc.Validate(doc.Root())
	return err
}

func TestRotationProbe(t *testing.T) {
	T0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	keyOld, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyNew, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyRogue, _ := rsa.GenerateKey(rand.Reader, 2048)

	// 旧证书: [T0, T0+90d]; 新证书: 同主体不同公钥, [T0+60d, T0+150d]; 重叠窗口 60..90
	derOld, certOld := mkCert(t, "sso.example.com", keyOld, 1, T0, T0.Add(90*day), nil, nil)
	derNew, certNew := mkCert(t, "sso.example.com", keyNew, 2, T0.Add(60*day), T0.Add(150*day), nil, nil)
	// 同密钥续期证书（DER 不同）
	derRenew, certRenew := mkCert(t, "sso.example.com", keyOld, 3, T0.Add(80*day), T0.Add(170*day), nil, nil)
	// 同主体攻击者证书
	derRogue, _ := mkCert(t, "sso.example.com", keyRogue, 4, T0, T0.Add(365*day), nil, nil)
	// CA + 叶子（检验是否存在链式构建）
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, caCert := mkCert(t, "Example CA", caKey, 10, T0, T0.Add(365*day), nil, nil)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	derLeaf, _ := mkCert(t, "sso.example.com", leafKey, 11, T0, T0.Add(30*day), caCert, caKey)

	docOld := signProbeDoc(t, keyOld, derOld)
	docNew := signProbeDoc(t, keyNew, derNew)
	docRenew := signProbeDoc(t, keyOld, derRenew)
	docRogue := signProbeDoc(t, keyRogue, derRogue)
	docLeaf := signProbeDoc(t, leafKey, derLeaf)

	at := func(d int) *time.Time { tm := T0.Add(time.Duration(d) * day); return &tm }
	report := func(name string, err error) {
		fmt.Printf("PROBE|%-58s|%v\n", name, err)
	}

	fmt.Println("=== A. 轮换时间线（KeyInfo 齐全）===")
	report("A1 t=T0+30d store{old}     doc(old)", tryValidate(docOld, []*x509.Certificate{certOld}, at(30)))
	report("A2 t=T0+30d store{old,new} doc(old)", tryValidate(docOld, []*x509.Certificate{certOld, certNew}, at(30)))
	report("A3 t=T0+30d store{old,new} doc(new) 新证未生效", tryValidate(docNew, []*x509.Certificate{certOld, certNew}, at(30)))
	report("A4 t=T0+75d store{old,new} doc(old) 重叠窗口", tryValidate(docOld, []*x509.Certificate{certOld, certNew}, at(75)))
	report("A5 t=T0+75d store{old,new} doc(new) 重叠窗口", tryValidate(docNew, []*x509.Certificate{certOld, certNew}, at(75)))
	report("A6 t=T0+75d store{old}     doc(new) 未加新证", tryValidate(docNew, []*x509.Certificate{certOld}, at(75)))
	report("A7 t=T0+100d store{old,new} doc(old) 旧证过期", tryValidate(docOld, []*x509.Certificate{certOld, certNew}, at(100)))
	report("A8 t=T0+100d store{new}    doc(new)", tryValidate(docNew, []*x509.Certificate{certNew}, at(100)))

	fmt.Println("=== B. 有效期边界（含端点性）===")
	nb := certOld.NotBefore
	na := certOld.NotAfter
	report("B1 t==NotBefore        doc(old)", tryValidate(docOld, []*x509.Certificate{certOld}, &nb))
	report("B2 t==NotBefore-1s     doc(old)", tryValidate(docOld, []*x509.Certificate{certOld}, ptrTime(nb.Add(-time.Second))))
	report("B3 t==NotAfter         doc(old)", tryValidate(docOld, []*x509.Certificate{certOld}, &na))
	report("B4 t==NotAfter+1s      doc(old)", tryValidate(docOld, []*x509.Certificate{certOld}, ptrTime(na.Add(time.Second))))

	fmt.Println("=== C. 缺省 KeyInfo ===")
	docNoKI1 := signProbeDoc(t, keyOld, derOld)
	stripKeyInfo(docNoKI1)
	report("C1 store{old}     无KeyInfo 单根", tryValidate(docNoKI1, []*x509.Certificate{certOld}, at(30)))
	docNoKI2 := signProbeDoc(t, keyOld, derOld)
	stripKeyInfo(docNoKI2)
	report("C2 store{old,new} 无KeyInfo 多根", tryValidate(docNoKI2, []*x509.Certificate{certOld, certNew}, at(75)))

	fmt.Println("=== D. 同密钥续期 / 同主体异钥 / CA 误用 ===")
	report("D1 store{old} doc(同密钥续期证) DER不等", tryValidate(docRenew, []*x509.Certificate{certOld}, at(85)))
	report("D2 store{old,renew} doc(续期证) 加入续期证", tryValidate(docRenew, []*x509.Certificate{certOld, certRenew}, at(85)))
	report("D3 store{old} doc(同主体异钥 rogue)", tryValidate(docRogue, []*x509.Certificate{certOld}, at(30)))
	report("D4 store{CA}  doc(叶子) 不做链构建", tryValidate(docLeaf, []*x509.Certificate{caCert}, at(15)))

	fmt.Println("=== E. 时钟缺省 ===")
	fmt.Printf("PROBE|certOld.Equal(certRenew)（同密钥续期）|%v\n", certOld.Equal(certRenew))
	fmt.Printf("PROBE|certOld.Equal(certNew)（同主体异钥）|%v\n", certOld.Equal(certNew))
}

func ptrTime(t time.Time) *time.Time { return &t }
