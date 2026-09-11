# LOGO — blue shield (2 min, GitHub web only)

Chat images can't be committed as files by me, so upload once yourself.
Your file: the blue rounded-square shield + android + checkmark you just sent.
Save it on your PC as `logo.png` (right-click > Save, 512×512 or bigger).

## Steps
1. In the GitHub repo, open `AndroidSecurityScanner/app/src/main/res/mipmap-xxxhdpi/`
   > Add file > Upload files > upload `logo.png` **renamed to `ic_launcher.png`** > Commit.
2. Repeat the SAME upload (same image, name `ic_launcher.png`) into:
   - `app/src/main/res/mipmap-xxhdpi/`
   - `app/src/main/res/drawable-nodpi/` (name it `logo.png` here, for dialogs/share)
3. Delete the vector placeholder folder so the PNG is used on Android 8+:
   open `app/src/main/res/mipmap-anydpi-v26/` > select both files > Delete > Commit.
4. Re-run Actions > Build Debug APK. Launcher + About card now show your blue logo.
   (About card loads the launcher icon dynamically — no code change needed.)

## Why PNG (not vector)?
Your logo has gradients + rounded squircle — tracing it to vector would lose
quality. PNG in xxxhdpi/xxhdpi is the standard quick path; Android scales down
for lower densities automatically.
