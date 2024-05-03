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



class Menu {

    #classLoader

    #activity

    #MATCH_PARENT

    #WRAP_CONTENT

    #mainLayout

    #leftMenuLayout

    #rightMenuLayout

    #leftMenuButtons

    #rightMenuOptions



    constructor(classLoader, activity) {

        this.#classLoader = classLoader

        this.#activity = activity

        this.#MATCH_PARENT = classLoader.LinearLayout_LayoutParams.MATCH_PARENT.value

        this.#WRAP_CONTENT = classLoader.LinearLayout_LayoutParams.WRAP_CONTENT.value

        this.#leftMenuButtons = []

        this.#rightMenuOptions = {}

        this.#createMainLayout()

    }



    #createMainLayout() {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#MATCH_PARENT)

        this.#mainLayout = this.#classLoader.LinearLayout.$new(this.#activity)

        this.#mainLayout.setLayoutParams(layoutParams)

        this.#mainLayout.setOrientation(this.#classLoader.LinearLayout.HORIZONTAL.value)

        this.#createLeftMenuLayout()

        this.#createRightMenuLayout()

    }



    #createLeftMenuLayout() {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(0, this.#MATCH_PARENT)

        layoutParams.weight = 1

        this.#leftMenuLayout = this.#classLoader.LinearLayout.$new(this.#activity)

        this.#leftMenuLayout.setLayoutParams(layoutParams)

        this.#leftMenuLayout.setOrientation(this.#classLoader.LinearLayout.VERTICAL.value)

    }



    #createRightMenuLayout() {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(0, this.#MATCH_PARENT)

        layoutParams.weight = 3

        this.#rightMenuLayout = this.#classLoader.LinearLayout.$new(this.#activity)

        this.#rightMenuLayout.setLayoutParams(layoutParams)

        this.#rightMenuLayout.setOrientation(this.#classLoader.LinearLayout.VERTICAL.value)

    }



    createLeftMenuButton(id, text, textColor, backgroundColor) {

        const button = this.#classLoader.TextView.$new(this.#activity)

        button.setText(this.#classLoader.String.$new(text))

        button.setTextColor(this.#classLoader.Color.parseColor(textColor))

        button.setBackgroundColor(this.#classLoader.Color.parseColor(backgroundColor))

        button.setPadding(20, 20, 20, 20)

        button.setGravity(this.#classLoader.Gravity.CENTER.value)

        button.setTextSize(18)

        button.setOnClickListener(this.#createLeftMenuButtonClickEvent(id))

        this.#leftMenuButtons.push({ id, button })

    }



    #createLeftMenuButtonClickEvent(id) {

        const classLoader = this.#classLoader

        const rightMenuLayout = this.#rightMenuLayout

        const rightMenuOptions = this.#rightMenuOptions

        return Java.registerClass({

            name: "com.example.LeftMenuClickListener_" + id,

            implements: [classLoader.View_OnClickListener],

            methods: {

                onClick(view) {

                    rightMenuLayout.removeAllViews()

                    const options = rightMenuOptions[id] || []

                    options.forEach(option => {

                        rightMenuLayout.addView(option)

                    })

                }

            }

        })

    }



    addRightMenuOption(leftMenuId, text, textColor, backgroundColor, callback) {

        const option = this.#classLoader.TextView.$new(this.#activity)

        option.setText(this.#classLoader.String.$new(text))

        option.setTextColor(this.#classLoader.Color.parseColor(textColor))

        option.setBackgroundColor(this.#classLoader.Color.parseColor(backgroundColor))

        option.setPadding(20, 20, 20, 20)

        option.setGravity(this.#classLoader.Gravity.CENTER.value)

        option.setTextSize(16)

        option.setOnClickListener(this.#createRightMenuOptionClickEvent(leftMenuId, callback))

        if (!this.#rightMenuOptions[leftMenuId]) {

            this.#rightMenuOptions[leftMenuId] = []

        }

        this.#rightMenuOptions[leftMenuId].push(option)

    }



    #createRightMenuOptionClickEvent(leftMenuId, callback) {

        return view => {

            const text = view.getText().toString()

            callback(text)

        }

    }



    #drawMainLayout() {

        this.#activity.setContentView(this.#mainLayout)

    }



    #drawLeftMenuLayout() {

        this.#mainLayout.addView(this.#leftMenuLayout)

        this.#leftMenuButtons.forEach(({ button }) => {

            this.#leftMenuLayout.addView(button)

        })

    }



    #drawRightMenuLayout() {

        this.#mainLayout.addView(this.#rightMenuLayout)

    }



    start() {

        this.#drawMainLayout()

        this.#drawLeftMenuLayout()

        this.#drawRightMenuLayout()

    }

}



Java.perform(function () {

    Java.scheduleOnMainThread(function () {

        const classLoader = getClassLoader()

        const mainActivity = getMainActivity(classLoader)

        const menu = new Menu(classLoader, mainActivity)

        

        // Adicionando botões de menu à esquerda

        menu.createLeftMenuButton("visual", "Visual", "#FFFFFF", "#333333")

        menu.createLeftMenuButton("extra", "Extra", "#FFFFFF", "#333333")

        

        // Adicionando opções de menu à direita para o botão "Visual"

        menu.addRightMenuOption("visual", "Roupa", "#FFFFFF", "#444444", option => {

            console.log("Opção selecionada:", option)

        })

        menu.addRightMenuOption("visual", "Sapato", "#FFFFFF", "#444444", option => {

            console.log("Opção selecionada:", option)

        })

        

        // Adicionando opções de menu à direita para o botão "Extra"

        menu.addRightMenuOption("extra", "Fuel", "#FFFFFF", "#444444", option => {

            console.log("Opção selecionada:", option)

        })

        menu.addRightMenuOption("extra", "Coin", "#FFFFFF", "#444444", option => {
        console.log("Opção selecionada:", option)

        })

        

        // Iniciar o menu

        menu.start()

    })

})

})