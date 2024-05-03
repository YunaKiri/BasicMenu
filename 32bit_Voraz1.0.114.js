class RadialMenu {

    #classLoader
    #activity
    #contentView
    #menuButton
    #menuLayout
    #options
    #colorOn
    #colorOff
    #menuOpen

    constructor(classLoader, activity) {
        this.#classLoader = classLoader
        this.#activity = activity
        this.#options = []
        this.#colorOn = "#00FF00"
        this.#colorOff = "#CCCCCC"
        this.#menuOpen = false
        this.#createContentView()
        this.#createMenuButton()
        this.#createMenuLayout()
    }

    #createContentView() {
        this.#contentView = this.#classLoader.LinearLayout.$new(this.#activity)
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#classLoader.ViewGroup_LayoutParams.MATCH_PARENT, this.#classLoader.ViewGroup_LayoutParams.MATCH_PARENT)
        this.#contentView.setLayoutParams(layoutParams)
        this.#contentView.setGravity(this.#classLoader.Gravity.CENTER.value)
        this.#contentView.setBackgroundColor(this.#classLoader.Color.TRANSPARENT.value)
    }

    #createMenuButton() {
        this.#menuButton = this.#classLoader.TextView.$new(this.#activity)
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT, this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT)
        this.#menuButton.setLayoutParams(layoutParams)
        this.#menuButton.setText("⚙️")
        this.#menuButton.setTextSize(30)
        this.#menuButton.setTextColor(this.#classLoader.Color.WHITE.value)
        this.#menuButton.setBackgroundColor(this.#classLoader.Color.BLACK.value)
        this.#menuButton.setGravity(this.#classLoader.Gravity.CENTER.value)
        const padding = pixelDensityToPixels(this.#activity, 10)
        this.#menuButton.setPadding(padding, padding, padding, padding)
        this.#menuButton.setOnClickListener(this.#createMenuClickListener())
    }

    #createMenuClickListener() {
        const classLoader = this.#classLoader
        const activity = this.#activity
        const menuLayout = this.#menuLayout
        return Java.registerClass({
            name: "com.example.MenuClickListener",
            implements: [classLoader.View_OnClickListener],
            methods: {
                onClick(view) {
                    if (!this.#menuOpen) {
                        activity.addContentView(menuLayout, menuLayout.getLayoutParams())
                        this.#menuOpen = true
                    } else {
                        activity.getWindow().getDecorView().removeView(menuLayout)
                        this.#menuOpen = false
                    }
                }
            }
        }).$new()
    }

    #createMenuLayout() {
        this.#menuLayout = this.#classLoader.LinearLayout.$new(this.#activity)
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT, this.#classLoader.ViewGroup_LayoutParams.WRAP_CONTENT)
        this.#menuLayout.setLayoutParams(layoutParams)
        this.#menuLayout.setOrientation(this.#classLoader.LinearLayout.HORIZONTAL.value)
        this.#menuLayout.setGravity(this.#classLoader.Gravity.CENTER.value)
        this.#menuLayout.setBackgroundColor(this.#classLoader.Color.TRANSPARENT.value)
        this.#menuLayout.setVisibility(this.#classLoader.View.GONE.value)
        this.#createMenuOptions()
    }

    #createMenuOptions() {
        for (let i = 0; i < 6; i++) {
            const option = this.#classLoader.TextView.$new(this.#activity)
            const optionSize = 100
            const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(pixelDensityToPixels(this.#activity, optionSize), pixelDensityToPixels(this.#activity, optionSize))
            const margin = pixelDensityToPixels(this.#activity, 10)
            layoutParams.setMargins(margin, margin, margin, margin)
            option.setLayoutParams(layoutParams)
            option.setText("Option " + (i + 1))
            option.setTextSize(20)
            option.setTextColor(this.#classLoader.Color.parseColor(this.#colorOff))
            option.setBackgroundColor(this.#classLoader.Color.parseColor(this.#colorOn))
            option.setGravity(this.#classLoader.Gravity.CENTER.value)
            option.setOnClickListener(this.#createOptionClickListener(i))
            this.#menuLayout.addView(option)
            this.#options.push(option)
        }
    }

    #createOptionClickListener(index) {
        const classLoader = this.#classLoader
        const colorOn = this.#colorOn
        const colorOff = this.#colorOff
        const options = this.#options
        return Java.registerClass({
            name: "com.example.OptionClickListener" + index,
            implements: [classLoader.View_OnClickListener],
            methods: {
                onClick(view) {
                    const option = options[index]
                    if (option.getTextColor() === classLoader.Color.parseColor(colorOff)) {
                        option.setTextColor(classLoader.Color.parseColor(colorOn))
                    } else {
                        option.setTextColor(classLoader.Color.parseColor(colorOff))
                    }
                }
            }
        }).$new()
    }

    start() {
        const mainLayout = this.#classLoader.ActivityThread.currentActivity().getWindow().getDecorView()
        mainLayout.addView(this.#contentView)
        this.#contentView.addView(this.#menuButton)
    }
}

Java.perform(function () {
    Java.scheduleOnMainThread(function () {
        const classLoader = getClassLoader()
        const mainActivity = getMainActivity(classLoader)
        const radialMenu = new RadialMenu(classLoader, mainActivity)
        radialMenu.start()
    })
})