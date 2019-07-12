/*
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package jw.pkcs11;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * How to initialize SunPKCS11 provider on Java 9 or later
 *
 * @author justy.wong
 *
 */

public class SunPKCS11Sample {

    public static void main(String[] args) {
        SunPKCS11Sample sample = new SunPKCS11Sample();

        sample.testWithConfigString();

        sample.testWithConfigFile();
    }

    private void testWithConfigString() {
        // config string start with "--"
        String config = "--name=opencryptoki\n" +
                "library=/usr/lib64/pkcs11/PKCS11_API.so\n" +
                "attributes=compatibility\n" +
                "slotListIndex=0\n";

        listCertificate(config, "password".toCharArray());
    }

    private void testWithConfigFile() {
        // filename as config
        String filename = "path-to/pkcs11.cfg";
        listCertificate(filename, "password".toCharArray());
    }

    private Provider newProvider(String config) {
        Provider p = Security.getProvider("SunPKCS11");
        return p.configure(config);
    }

    private void listCertificate(String config, char[] pin) {
        try {
            Provider provider = newProvider(config);
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, pin);
            for (Enumeration<String> en = ks.aliases(); en.hasMoreElements(); ) {
                String alias = en.nextElement();
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                System.out.println("alias = " + alias);
                System.out.println("cert = " + cert.getSubjectDN());
                System.out.println("is key entry : " + ks.isKeyEntry(alias));
            }
        } catch (Exception e) {
            System.out.println("Fail to load keystore : " + e);
            e.printStackTrace();
        }
    }
}
