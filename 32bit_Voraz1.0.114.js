function getClassLoader() {

    const classLoader = {

        Gravity: Java.use("android.view.Gravity"),

        TextView: Java.use("android.widget.TextView"),

        LinearLayout: Java.use("android.widget.LinearLayout"),

        ViewGroup_LayoutParams: Java.use("android.view.ViewGroup$LayoutParams"),

        LinearLayout_LayoutParams: Java.use("android.widget.LinearLayout$LayoutParams"),

        Color: Java.use("android.graphics.Color"),

        ActivityThread: Java.use("android.app.ActivityThread"),

        ActivityThread_ActivityClientRecord: Java.use("android.app.ActivityThread$ActivityClientRecord"),

        View_OnTouchListener: Java.use("android.view.View$OnTouchListener"),

        MotionEvent: Java.use("android.view.MotionEvent"),

        String: Java.use("java.lang.String"),

        ScrollView: Java.use("android.widget.ScrollView"),

        View_OnClickListener: Java.use("android.view.View$OnClickListener"),

        SeekBar: Java.use("android.widget.SeekBar") // Adicionando definição para SeekBar

    }

    return classLoader

}



function pixelDensityToPixels(context, dp) {

    const density = context.getResources().getDisplayMetrics().density.value

    return parseInt(dp * density)

}



function getMainActivity(classLoader) {

    const activityThread = classLoader.ActivityThread.sCurrentActivityThread.value

    const mActivities = activityThread.mActivities.value

    const activityClientRecord = Java.cast(mActivities.valueAt(0), classLoader.ActivityThread_ActivityClientRecord)

    return activityClientRecord.activity.value

}



class TextEditor {

    #classLoader

    #activity

    #dialog

    #textView

    #editText

    #button

    #errorTextView



    constructor(classLoader, activity) {

        this.#classLoader = classLoader

        this.#activity = activity

        this.#createDialog()

        this.#createTextView()

        this.#createEditText()

        this.#createButton()

        this.#createErrorTextView()

    }



    #createDialog() {

        this.#dialog = this.#classLoader.TextView.$new(this.#activity)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#classLoader.ViewGroup_LayoutParams.MATCH_PARENT, this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT)

        this.#dialog.setLayoutParams(layoutParams)

        this.#dialog.setGravity(this.#classLoader.Gravity.CENTER.value)

        this.#dialog.setBackgroundColor(this.#classLoader.Color.WHITE.value)

        this.#dialog.setPadding(50, 50, 50, 50)

        this.#dialog.setElevation(20)

    }



    #createTextView() {

        this.#textView = this.#classLoader.TextView.$new(this.#activity)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#classLoader.ViewGroup_LayoutParams.MATCH_PARENT, this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT)

        this.#textView.setLayoutParams(layoutParams)

        this.#textView.setText("Insira a chave:")

        this.#textView.setTextSize(20)

        this.#textView.setTextColor(this.#classLoader.Color.BLACK.value)

        this.#textView.setGravity(this.#classLoader.Gravity.CENTER.value)

        this.#dialog.addView(this.#textView)

    }



    #createEditText() {

        this.#editText = this.#classLoader.TextView.$new(this.#activity)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#classLoader.ViewGroup_LayoutParams.MATCH_PARENT, this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT)

        this.#editText.setLayoutParams(layoutParams)

        this.#editText.setHint("Digite sua chave aqui...")

        this.#editText.setPadding(20, 20, 20, 20)

        this.#editText.setSingleLine(true)

        this.#editText.setBackground(null)

        this.#editText.setBackgroundColor(this.#classLoader.Color.parseColor("#F5F5F5"))

        this.#editText.setTextColor(this.#classLoader.Color.BLACK.value)

        this.#dialog.addView(this.#editText)

    }



    #createButton() {

        this.#button = this.#classLoader.TextView.$new(this.#activity)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT, this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT)

        layoutParams.setMargins(0, 50, 0, 0)

        this.#button.setLayoutParams(layoutParams)

        this.#button.setText("Confirmar")

        this.#button.setTextSize(18)

        this.#button.setTextColor(this.#classLoader.Color.WHITE.value)

        this.#button.setBackgroundColor(this.#classLoader.Color.parseColor("#009688"))

        this.#button.setPadding(40, 20, 40, 20)

        this.#button.setGravity(this.#classLoader.Gravity.CENTER.value)

        this.#button.setOnClickListener(

            this.#classLoader.View_OnClickListener.onClick.overload('android.view.View', ).implementation = () => {

                const key = this.#editText.getText().toString()

                if (key === "sua_chave_aqui") {

                    this.#closeDialog()

                    this.#successCallback(key)

                } else {

                    this.#showErrorMessage("Chave inválida!")

                }

            }

        )

        this.#dialog.addView(this.#button)

    }



    #createErrorTextView() {

        this.#errorTextView = this.#classLoader.TextView.$new(this.#activity)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#classLoader.ViewGroup_LayoutParams.MATCH_PARENT, this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT)

        layoutParams.setMargins(0, 50, 0, 0)

        this.#errorTextView.setLayoutParams(layoutParams)

        this.#errorTextView.setTextSize(16)

        this.#errorTextView.setTextColor(this.#classLoader.Color.RED.value)

        this.#errorTextView.setGravity(this.#classLoader.Gravity.CENTER.value)

        this.#dialog.addView(this.#errorTextView)

    }



    #closeDialog() {

        this.#activity.runOnUiThread(() => {

            this.#dialog.dismiss()

        })

    }



    #showErrorMessage(message) {

        this.#activity.runOnUiThread(() => {

            this.#errorTextView.setText(message)

        })

    }



    setTitle(title) {

        this.#activity.runOnUiThread(() => {

            this.#textView.setText(title)

        })

    }



    setPlaceholder(placeholder) {

        this.#activity.runOnUiThread(() => {

            this.#editText.setHint(placeholder)

        })

    }



    setButtonText(text) {

        this.#activity.runOnUiThread(() => {

            this.#button.setText(text)

        })

    }



    setButtonClickListener(callback) {

        this.#successCallback = callback

    }



    show() {

        this.#activity.runOnUiThread(() => {

            const window = this.#activity.getWindow()

            const decorView = window.getDecorView()

            this.#dialog.show()

        })

    }



    close() {

        this.#closeDialog()

    }

}



Java.perform(function () {

    Java.scheduleOnMainThread(function () {
        
        const classLoader = getClassLoader();

        const mainActivity = getMainActivity(classLoader);

        const textEditor = new TextEditor(classLoader, mainActivity);

        textEditor.setTitle("Insira a chave:");

        textEditor.setPlaceholder("Digite sua chave aqui...");

        textEditor.setButtonText("Confirmar");

        textEditor.setButtonClickListener(function (key) {
            if (key === "sua_chave_aqui") {

                const menu = new Menu(classLoader, mainActivity);

                // Set the title and colormenu.createMenuOptionsLayout("#009688", "#75757B");

                menu.createMenuStart("Menu", 18, "#75757B");

                menu.createMenuLayout("#F5F5F5", 16);

                menu.createMenuBarLayout("#009688");

                menu.createMenuBarTitle("Título do Menu", "#FFFFFF", 18);

                menu.addOption("option1", "Opção 1", {
                    on() {
                        console.log("Opção 1 ativada");
                    },
                    off() {
                        console.log("Opção 1 desativada");
                    }
                });

                menu.addOption("option2", "Opção 2", {
                    on() {
                        console.log("Opção 2 ativada");
                    },
                    off() {
                        console.log("Opção 2 desativada");
                    }
                });

                menu.addText("Ajuste de volume", 14, "#000000");

                menu.addSeekBar("Volume", 50, 0, 100, function (value, type) {
                    console.log("Novo valor do volume:", value, "Tipo:", type);
                });

                menu.start();
            } else {
                textEditor.show();
            }
        });

        textEditor.show();
    });
});