# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('C:/Users/gabri/ClarityPC/src/clarity/ui/gui/web', 'clarity/ui/gui/web')]
binaries = []
hiddenimports = []

tmp_ret = collect_all('clarity')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

try:
    tmp_wv = collect_all('webview')
    datas += tmp_wv[0]; binaries += tmp_wv[1]; hiddenimports += tmp_wv[2]
except Exception:
    pass

a = Analysis(
    ['C:/Users/gabri/ClarityPC/entrypoint.py'],
    pathex=['C:/Users/gabri/ClarityPC/src'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ClarityPC',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='C:/Users/gabri/ClarityPC/package/clarity.ico',
    manifest='C:/Users/gabri/ClarityPC/package/clarity.exe.manifest',
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ClarityPC',
)
