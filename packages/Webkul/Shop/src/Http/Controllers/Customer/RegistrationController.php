<?php

namespace Webkul\Shop\Http\Controllers\Customer;

use Cookie;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Webkul\Core\Repositories\SubscribersListRepository;
use Webkul\Customer\Repositories\CustomerGroupRepository;
use Webkul\Customer\Repositories\CustomerRepository;
use Webkul\Shop\Http\Controllers\Controller;
use Webkul\Shop\Http\Requests\Customer\RegistrationRequest;
use Webkul\Shop\Mail\Customer\EmailVerificationNotification;
use Webkul\Shop\Mail\Customer\RegistrationNotification;

class RegistrationController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct(
        protected CustomerRepository $customerRepository,
        protected CustomerGroupRepository $customerGroupRepository,
        protected SubscribersListRepository $subscriptionRepository
    ) {}

    /**
     * Opens up the user's sign up form.
     *
     * @return \Illuminate\View\View
     */
    public function index()
    {
        return view('shop::customers.sign-up');
    }

    /**
     * Method to store user's sign up form data to DB.
     *
     * @return \Illuminate\Http\Response
     */
    public function store(RegistrationRequest $registrationRequest)
    {
        $customerGroup = core()->getConfigData('customer.settings.create_new_account_options.default_group');

        $data = array_merge($registrationRequest->only([
            'first_name',
            'last_name',
            'email',
            'password_confirmation',
            'is_subscribed',
        ]), [
            'password'                  => bcrypt(request()->input('password')),
            'api_token'                 => Str::random(80),
            'is_verified'               => ! core()->getConfigData('customer.settings.email.verification'),
            'customer_group_id'         => $this->customerGroupRepository->findOneWhere(['code' => $customerGroup])->id,
            'channel_id'                => core()->getCurrentChannel()->id,
            'token'                     => md5(uniqid(rand(), true)),
            'subscribed_to_news_letter' => (bool) request()->input('is_subscribed'),
        ]);

        Event::dispatch('customer.registration.before');

        $customer = $this->customerRepository->create($data);

        if (isset($data['is_subscribed'])) {
            $subscription = $this->subscriptionRepository->findOneWhere(['email' => $data['email']]);

            if ($subscription) {
                $this->subscriptionRepository->update([
                    'customer_id' => $customer->id,
                ], $subscription->id);
            } else {
                Event::dispatch('customer.subscription.before');

                $subscription = $this->subscriptionRepository->create([
                    'email'         => $data['email'],
                    'customer_id'   => $customer->id,
                    'channel_id'    => core()->getCurrentChannel()->id,
                    'is_subscribed' => 1,
                    'token'         => uniqid(),
                ]);

                Event::dispatch('customer.subscription.after', $subscription);
            }
        }

        Event::dispatch('customer.create.after', $customer);

        Event::dispatch('customer.registration.after', $customer);

        if (core()->getConfigData('emails.general.notifications.emails.general.notifications.verification')) {
            session()->flash('success', trans('shop::app.customers.signup-form.success-verify'));
        } else {
            session()->flash('success', trans('shop::app.customers.signup-form.success'));
        }

        return redirect()->route('shop.customer.session.index');
    }

    public function registrationFromOrder($params)
    {
        $data = $params['billing'];
        // Ubah format data agar sesuai dengan yang diharapkan
        $registrationData = [
            'first_name' => $data['first_name'],
            'last_name' => $data['last_name'],
            'email' => $data['email'],
            'is_subscribed' => $data['is_subscribed'] ?? false
        ];

        // Generate password otomatis
        $password = $this->generate_password(true, 10);

        $customerGroup = core()->getConfigData('customer.settings.create_new_account_options.default_group');
        $formattedData = array_merge($registrationData, [
            'password' => bcrypt($password),
            'password_confirmation' => $password,
            'api_token' => Str::random(80),
            'is_verified' => !core()->getConfigData('customer.settings.email.verification'),
            'customer_group_id' => $this->customerGroupRepository->findOneWhere(['code' => $customerGroup])->id,
            'channel_id' => core()->getCurrentChannel()->id,
            'token' => md5(uniqid(rand(), true)),
            'subscribed_to_news_letter' => (bool)($registrationData['is_subscribed'] ?? false),
        ]);

        Event::dispatch('customer.registration.before');
        $customer = $this->customerRepository->create($formattedData);

        if (isset($formattedData['is_subscribed']) && $formattedData['is_subscribed']) {
            $subscription = $this->subscriptionRepository->findOneWhere(['email' => $formattedData['email']]);
            if ($subscription) {
                $this->subscriptionRepository->update([
                    'customer_id' => $customer->id,
                ], $subscription->id);
            } else {
                Event::dispatch('customer.subscription.before');
                $subscription = $this->subscriptionRepository->create([
                    'email' => $formattedData['email'],
                    'customer_id' => $customer->id,
                    'channel_id' => core()->getCurrentChannel()->id,
                    'is_subscribed' => 1,
                    'token' => uniqid(),
                ]);
                Event::dispatch('customer.subscription.after', $subscription);
            }
        }

        Event::dispatch('customer.create.after', $customer);
        Event::dispatch('customer.registration.after', $customer);

        // Simpan password yang digenerate untuk dikirim ke email pelanggan
        $customer->generated_password = $password;

        // Format respons customer sesuai yang diinginkan
        $customerResponse = [
            'first_name' => $customer->first_name,
            'last_name' => $customer->last_name,
            'email' => $customer->email,
            'generated_password' => $password // Jika ingin menyertakan password yang digenerate
        ];

        if (core()->getConfigData('emails.general.notifications.emails.general.notifications.verification')) {
            session()->flash('success', trans('shop::app.customers.signup-form.success-verify'));
        } else {
            session()->flash('success', trans('shop::app.customers.signup-form.success'));
        }

        return [
            $customerResponse
        ];
    }

    private function generate_password($addSpecialChars = false, $length = 8)
    {
        $alphabet = "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";
        $specialChars = "@*%&!-_";
        $pass = [];
        $alphaLength = strlen($alphabet) - 1;

        for ($i = 0; $i < $length; $i++) {
            $n = rand(0, $alphaLength);
            $pass[] = $alphabet[$n];
        }

        // Tambahkan karakter khusus jika diminta
        if ($addSpecialChars) {
            $specialCharsLength = strlen($specialChars) - 1;
            $randomPos = rand(0, count($pass) - 1);
            $n = rand(0, $specialCharsLength);
            $pass[$randomPos] = $specialChars[$n];
        }

        return implode('', $pass);
    }

    /**
     * Method to verify account.
     *
     * @param  string  $token
     * @return \Illuminate\Http\Response
     */
    public function verifyAccount($token)
    {
        $customer = $this->customerRepository->findOneByField('token', $token);

        if ($customer) {
            $this->customerRepository->update([
                'is_verified' => 1,
                'token'       => null,
            ], $customer->id);

            if ((bool) core()->getConfigData('emails.general.notifications.emails.general.notifications.registration')) {
                Mail::queue(new RegistrationNotification($customer));
            }

            $this->customerRepository->syncNewRegisteredCustomerInformation($customer);

            session()->flash('success', trans('shop::app.customers.signup-form.verified'));
        } else {
            session()->flash('warning', trans('shop::app.customers.signup-form.verify-failed'));
        }

        return redirect()->route('shop.customer.session.index');
    }

    /**
     * Resend verification email.
     *
     * @param  string  $email
     * @return \Illuminate\Http\Response
     */
    public function resendVerificationEmail($email)
    {
        $verificationData = [
            'email' => $email,
            'token' => md5(uniqid(rand(), true)),
        ];

        $customer = $this->customerRepository->findOneByField('email', $email);

        $this->customerRepository->update(['token' => $verificationData['token']], $customer->id);

        try {
            Mail::queue(new EmailVerificationNotification($verificationData));

            if (Cookie::has('enable-resend')) {
                \Cookie::queue(\Cookie::forget('enable-resend'));
            }

            if (Cookie::has('email-for-resend')) {
                \Cookie::queue(\Cookie::forget('email-for-resend'));
            }
        } catch (\Exception $e) {
            report($e);

            session()->flash('error', trans('shop::app.customers.signup-form.verification-not-sent'));

            return redirect()->back();
        }

        session()->flash('success', trans('shop::app.customers.signup-form.verification-sent'));

        return redirect()->back();
    }
}
