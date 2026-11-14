"""Signing order and external final artifact bindings using inert owned bytes."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('maintenance_packaging',ROOT/'tools/package_fskit.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class Signing(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='maintenance-signing-',dir=ROOT.parent)
        self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name).resolve();self.base.chmod(0o700)
        self.app=self.base/'StallionFS.app';self.app.mkdir(mode=0o755)
        _,self.observer,self.o=p._maintenance_source();self.roles=self.o['RESOURCE_ROLES']
        self.write(self.roles['native'],b'unsigned',0o755)
        self.write(self.roles['observer'],self.observer)
        self.write(self.roles['compatibility'],b'compatibility')
        self.write('Contents/Resources/Runtime/Git/bin/git',b'fake-git',0o755)
        payload=p._runtime_bundle().git_payload(self.app/'Contents/Resources/Runtime/Git')
        self.write('Contents/Resources/Runtime/runtime.json',json.dumps(dict(schema=2,source_build_id='a'*64,
            git=dict(self.o['GIT_CONTRACT'],input_inventory_sha256='9b9401eaea9d2f2b3e88c8c87509b52414b5522016c505718c050cd562725700',
                     payload_entries=payload['entries'],payload_sha256=payload['sha256']))).encode())
        self.write('Contents/Resources/Runtime/CPython/bin/python3.13',b'\xcf\xfa\xed\xfefake signed python',0o755)
        self.write('Contents/Extensions/StallionFS.appex/Contents/Info.plist',b'fixture')

    def write(self,name,data,mode=0o644):
        path=self.app/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(mode)
        return path

    def archive(self):
        rows=p._runtime_inventory(self.app);target=self.base/'exact.zip'
        with zipfile.ZipFile(target,'w') as archive:
            root=zipfile.ZipInfo(self.app.name+'/');root.create_system=3
            root.external_attr=(stat.S_IFDIR|0o755)<<16;archive.writestr(root,b'')
            for row in rows:
                name=self.app.name+'/'+row['path']+('/' if row['type']=='dir' else '')
                item=zipfile.ZipInfo(name);item.create_system=3
                item.external_attr=((stat.S_IFDIR if row['type']=='dir' else stat.S_IFREG)|int(row['mode'],8))<<16
                archive.writestr(item,b'' if row['type']=='dir' else (self.app/row['path']).read_bytes())
        target.chmod(0o600);return target,rows

    def test_leaf_signs_before_outer_seal_and_literal_requirements_are_explicit(self):
        calls=[]
        def tool(argv,directory):
            calls.append(argv)
            if '--sign' in argv:self.write(self.roles['native'],b'signed',0o755)
            else:self.assertTrue(argv[argv.index('-R')+1].startswith('=anchor apple generic'))
            return ''
        with patch.object(p,'_tool_output',side_effect=tool):
            result=p.sign_maintenance_leaf(self.app,expected_unsigned_sha256=hashlib.sha256(b'unsigned').hexdigest(),
                identity='Developer ID Application: Fixture',expected_publisher=self.o['PUBLISHER_TEAM'])
        self.assertTrue(result['outer_seal_pending']);self.assertEqual(len(calls),2)
        self.assertEqual(result['sha256'],hashlib.sha256(b'signed').hexdigest())
        self.write('Contents/_CodeSignature/CodeResources',b'seal')
        with self.assertRaisesRegex(ValueError,'before sealing'):
            p.sign_maintenance_leaf(self.app,expected_unsigned_sha256=result['sha256'],identity='Fixture',expected_publisher=self.o['PUBLISHER_TEAM'])
        with self.assertRaisesRegex(ValueError,'publisher'):
            p.sign_maintenance_leaf(self.app,expected_unsigned_sha256=result['sha256'],identity='Fixture',expected_publisher='OTHERTEAM0')

    def test_final_bindings_require_exact_archive_and_verify_nested_publishers(self):
        self.write('Contents/_CodeSignature/CodeResources',b'seal')
        archive,rows=self.archive();calls=[]
        def verify(argv,directory):
            self.assertIn('--verify',argv);self.assertTrue(argv[argv.index('-R')+1].startswith('='));calls.append(argv);return ''
        with patch.object(p,'_tool_output',side_effect=verify):
            mapping=p.final_maintenance_bindings(self.app,archive,expected_publisher=self.o['PUBLISHER_TEAM'])
        self.assertEqual(mapping['inventory'],rows);self.assertEqual(mapping['public_upgrade_support'],[])
        self.assertEqual(mapping['artifact']['native_sha256'],hashlib.sha256(b'unsigned').hexdigest())
        self.assertTrue(any(str(self.app/'Contents/Resources/Runtime/CPython/bin/python3.13')==a[-1] for a in calls))
        self.write('Contents/Resources/Runtime/runtime.json',b'stale-relative-to-archive')
        with patch.object(p,'_tool_output',side_effect=verify),self.assertRaises(ValueError):
            p.final_maintenance_bindings(self.app,archive,expected_publisher=self.o['PUBLISHER_TEAM'])

    def test_unsealed_wrong_publisher_tampered_leaf_and_zip_scope_refuse(self):
        archive,rows=self.archive()
        with self.assertRaises(OSError):p.final_maintenance_bindings(self.app,archive,expected_publisher=self.o['PUBLISHER_TEAM'])
        self.write('Contents/_CodeSignature/CodeResources',b'seal');archive,rows=self.archive()
        with self.assertRaisesRegex(ValueError,'publisher'):
            p.final_maintenance_bindings(self.app,archive,expected_publisher='OTHERTEAM0')
        def denied(argv,directory):
            if argv[-1].endswith('/stallionfs-maintenance'):raise ValueError('tampered or wrong publisher')
            return ''
        with patch.object(p,'_tool_output',side_effect=denied),self.assertRaisesRegex(ValueError,'tampered'):
            p.final_maintenance_bindings(self.app,archive,expected_publisher=self.o['PUBLISHER_TEAM'])
        with zipfile.ZipFile(archive,'a') as zipped:zipped.writestr('../foreign',b'bad')
        with self.assertRaises(ValueError):p.verify_maintenance_archive(archive.read_bytes(),rows,self.app.name)

    def test_every_macho_encoding_requires_independent_nested_publisher(self):
        self.write('Contents/_CodeSignature/CodeResources',b'seal')
        encodings=(bytes.fromhex(value) for value in
            ('cffaedfe','cefaedfe','feedfacf','feedface','cafebabe','bebafeca','cafebabf','bfbafeca'))
        names=[]
        for index,magic in enumerate(encodings):
            name='Contents/Resources/Runtime/Additional/code-'+str(index)
            self.write(name,magic+b'inert encoded native member',0o755)
            names.append(name)
        archive,_=self.archive();calls=[]
        def verify(argv,directory):
            calls.append(argv)
            self.assertTrue(argv[argv.index('-R')+1].startswith('=anchor apple generic'))
            return ''
        with patch.object(p,'_tool_output',side_effect=verify):
            mapping=p.final_maintenance_bindings(self.app,archive,expected_publisher=self.o['PUBLISHER_TEAM'])
        self.assertTrue(set(names)<={row['path'] for row in mapping['signing_roles']})
        for name in names:
            self.assertTrue(any(argv[-1]==str(self.app/name) for argv in calls),name)
        for index in (3,6,7):
            def denied(argv,directory):
                if argv[-1]==str(self.app/names[index]):raise ValueError('nested publisher refused')
                return ''
            with self.subTest(encoding=names[index]),patch.object(p,'_tool_output',side_effect=denied), \
                    self.assertRaisesRegex(ValueError,'nested publisher refused'):
                p.final_maintenance_bindings(self.app,archive,expected_publisher=self.o['PUBLISHER_TEAM'])


    def test_archive_requires_empty_directories(self):
        self.write('Contents/empty/.temporary',b'')
        (self.app/'Contents/empty/.temporary').unlink()
        archive,rows=self.archive()
        result=io.BytesIO()
        with zipfile.ZipFile(archive) as original,zipfile.ZipFile(result,'w') as changed:
            for item in original.infolist():
                if item.filename != 'StallionFS.app/Contents/empty/':changed.writestr(item,original.read(item))
        with self.assertRaisesRegex(ValueError,'incomplete'):
            p.verify_maintenance_archive(result.getvalue(),rows,self.app.name)


    def test_zip_directory_type_mode_and_payload_must_be_exact(self):
        archive,rows=self.archive()
        for target,mode,payload in (('StallionFS.app/',stat.S_IFLNK|0o755,b''),
                                   ('StallionFS.app/',stat.S_IFDIR|0o777,b''),
                                   ('StallionFS.app/Contents/',stat.S_IFLNK|0o755,b''),
                                   ('StallionFS.app/Contents/',stat.S_IFDIR|0o755,b'x')):
            data=io.BytesIO()
            with zipfile.ZipFile(archive) as original,zipfile.ZipFile(data,'w') as changed:
                for row in original.infolist():
                    value=original.read(row)
                    if row.filename == target:row.external_attr=mode<<16;value=payload
                    changed.writestr(row,value)
            with self.subTest(target=target,mode=mode,payload=payload),self.assertRaises(ValueError):
                p.verify_maintenance_archive(data.getvalue(),rows,self.app.name)


    def test_zip_nonunix_file_creator_refuses(self):
        archive,rows=self.archive();data=io.BytesIO()
        with zipfile.ZipFile(archive) as original,zipfile.ZipFile(data,'w') as changed:
            for row in original.infolist():
                value=original.read(row)
                if row.filename.endswith('/stallionfs-maintenance'):row.create_system=0
                changed.writestr(row,value)
        with self.assertRaises(ValueError):p.verify_maintenance_archive(data.getvalue(),rows,self.app.name)


    def test_native_package_requirement_executes_with_literal_prefix(self):
        import ast
        tree=ast.parse((ROOT/'stallionfs/_native.py').read_bytes())
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='package_argv')
        namespace={'Path':Path,'__package__':'stallionfs'}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'package_argv','exec'),namespace)
        argv=namespace['package_argv']('/Applications/StallionFS.app/Contents/MacOS/StallionFS')
        self.assertEqual(argv[:5],['/usr/bin/codesign','--verify','--deep','--strict','-R'])
        self.assertTrue(argv[5].startswith('=anchor apple generic'))
        self.assertEqual(argv[-1],'/Applications/StallionFS.app')


    @unittest.skipUnless(os.path.exists('/usr/sbin/mtree'),'Native mtree required')
    def test_no_python_exact_layout_commands(self):
        import shutil
        import subprocess
        document=(ROOT/'docs/fskit-maintenance.md').read_text()
        commands=document.split('<!-- exact-layout-decision -->',1)[1].split('```sh',1)[1].split('```',1)[0]
        self.write('Contents/empty/.temporary',b'');(self.app/'Contents/empty/.temporary').unlink()
        for index,change in enumerate(('exact','bytes','mode','empty-dir','extra','hardlink','symlink')):
            target=self.base/('target-'+str(index)+'.app');shutil.copytree(self.app,target,symlinks=True)
            member=target/'Contents/Resources/Runtime/runtime.json'
            if change=='bytes':member.write_bytes(b'different same-publisher descriptor')
            elif change=='mode':member.chmod(0o600)
            elif change=='empty-dir':(target/'Contents/empty').rmdir()
            elif change=='extra':(target/'unlisted').write_bytes(b'extra')
            elif change=='hardlink':os.link(member,self.base/('outside-'+str(index)))
            elif change=='symlink':member.unlink();member.symlink_to('/outside')
            environment={'PATH':'/usr/bin:/bin:/usr/sbin','LANG':'C','STAGED':str(self.app),
                'APP_TO_CHECK':str(target),'LAYOUT_SPEC':str(self.base/('layout-'+str(index)))}
            result=subprocess.run(['/bin/sh','-c',commands],env=environment,capture_output=True,timeout=15)
            with self.subTest(change=change):self.assertEqual(result.returncode==0,change=='exact',result.stderr.decode())


if __name__=='__main__':unittest.main()
