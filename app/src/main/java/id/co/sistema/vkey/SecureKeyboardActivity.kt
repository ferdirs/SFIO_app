package id.co.sistema.vkey

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.vkey.android.secure.keyboard.VKeySecureKeypad

class SecureKeyboardActivity : AppCompatActivity() {

    private lateinit var btn_kb: Button
    private lateinit var et_kb: EditText
    private lateinit var tv_kb: TextView

    private lateinit var tv_kp : TextView
    private lateinit var et_kp : EditText
    private lateinit var bt_kp : Button

    private lateinit var tv_kpn : TextView
    private lateinit var et_kpn : EditText
    private lateinit var bt_kpn : Button

    init {
        VKeySecureKeypad.VKSecureKeyboardLayout = R.xml.vk_input1
        VKeySecureKeypad.VKSecureEditTextAttrs = R.styleable.VKSecureEditText
        VKeySecureKeypad.VKSecureEditTextInDialogIdx = R.styleable.VKSecureEditText_inDialog
        VKeySecureKeypad.VKSecureEditTextRandomizedIdx = R.styleable.VKSecureEditText_randomized
        VKeySecureKeypad.qwertyLayout = R.xml.vk_keyboard_qwerty
        VKeySecureKeypad.qwertyCapsLayout = R.xml.vk_keyboard_qwerty_caps
        VKeySecureKeypad.numbersSymbolsLayout = R.xml.vk_keyboard_numbers_symbols
        VKeySecureKeypad.numbersSymbolsLayout2 = R.xml.vk_keyboard_numbers_symbols2
        VKeySecureKeypad.numbersLayout = R.xml.vk_keyboard_numbers
        VKeySecureKeypad.numbersLayoutHorizontal = R.xml.vk_keyboard_numbers_symbol_horizontal
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_secure_keyboard)

        btn_kb = findViewById(R.id.bt_1)
        tv_kb = findViewById(R.id.tv_res)
        et_kb = findViewById(R.id.et_securekb)

        bt_kp = findViewById(R.id.bt_2)
        tv_kp = findViewById(R.id.tv_reskp)
        et_kp = findViewById(R.id.et_securekp)

        bt_kpn = findViewById(R.id.bt_3)
        tv_kpn = findViewById(R.id.tv_reskpn)
        et_kpn = findViewById(R.id.et_securekpn)

        btn_kb.setOnClickListener {
            tv_kb.text =et_kb.text
        }

        bt_kp.setOnClickListener {
            tv_kp.text = et_kp.text
        }

        bt_kpn.setOnClickListener {
            tv_kpn.text = et_kpn.text
        }

    }
}