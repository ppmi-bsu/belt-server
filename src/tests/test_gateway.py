# -*- coding: utf-8 -*-

from unittest import TestCase
import jbelt


test_xml = u'''<?xml version="1.0" encoding="UTF-8"?>
<project >
    <modelVersion>4.0.0</modelVersion>

    <groupId>jbelt</groupId>
    <artifactId>jbelt</artifactId>
    <version>1.0-SNAPSHOT</version>


    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>3.8.1</version>
            <scope>test</scope>
        </dependency>


        <dependency>
            <groupId>com.sun.jna</groupId>
            <artifactId>jna</artifactId>
            <version>3.0.9</version>
        </dependency>

        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk16</artifactId>
            <version>1.46</version>
        </dependency>

        <dependency>
            <groupId>org.python</groupId>
            <artifactId>jython</artifactId>
            <version>2.5.4-rc1</version>
        </dependency>

         <dependency>
            <groupId>commons-logging</groupId>
            <artifactId>commons-logging</artifactId>
            <version>1.1.3</version>
        </dependency>

         <dependency>
            <groupId>org.codehaus.groovy</groupId>
            <artifactId>groovy-all</artifactId>
            <version>2.2.2</version>
        </dependency>
        <dependency>
            <groupId>xalan</groupId>
            <artifactId>xalan</artifactId>
            <version>2.7.1</version>
        </dependency>
        <dependency>
            <groupId>org.apache.santuario</groupId>
            <artifactId>xmlsec</artifactId>
            <version>1.5.6</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.1</version>
                <configuration>
                    <source>1.5</source>
                    <target>1.5</target>
                </configuration>
            </plugin>
        </plugins>

    </build>

</project>
'''


class BeltGatewayTestCase(TestCase):

    def test_sign(self):
        xml = jbelt.sign(test_xml)
        print(xml)
        self.assertTrue(jbelt.verify(xml))

    def test_key_gen(self):
        keys = jbelt.genKeys()
        self.assertTrue(str(keys['priv']))
        self.assertTrue(str(keys['pub']))
        self.assertTrue(isinstance(keys['priv'], bytearray))
        self.assertTrue(isinstance(keys['pub'], bytearray))
        self.assertEqual(len(keys['priv']), 32)

        self.assertEqual(len(keys['pub']), 64)
        self.assertNotEqual(keys['pub'], keys['priv'])

    def test_key_calc(self):
        keys = jbelt.genKeys()
        self.assertEqual(jbelt.calc_keys(keys['priv']).getPublic().getBytes(),
                         keys['pub'])

    def test_encryption(self):
        keys = jbelt.genKeys()
        ecrypted = jbelt.enc(test_xml, str(keys['pub']))
        jbelt.dec(ecrypted, str(keys['priv']))
